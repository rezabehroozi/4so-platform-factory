//go:build cgo && linux

package pgdriver

/*
#cgo CFLAGS: -I/usr/include/postgresql
#cgo LDFLAGS: -lpq
#include <stdlib.h>
#include <libpq-fe.h>
*/
import "C"

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const driverName = "4so-libpq"

func init() { sql.Register(driverName, &pqDriver{}) }

func Name() string        { return driverName }
func Available() bool     { return true }
func Description() string { return "built-in libpq PostgreSQL adapter" }

type pqDriver struct{}

func (d *pqDriver) Open(dsn string) (driver.Conn, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("PostgreSQL DSN is empty")
	}
	cDSN := C.CString(dsn)
	defer C.free(unsafe.Pointer(cDSN))
	conn := C.PQconnectdb(cDSN)
	if conn == nil {
		return nil, errors.New("libpq returned a nil connection")
	}
	if C.PQstatus(conn) != C.CONNECTION_OK {
		msg := strings.TrimSpace(C.GoString(C.PQerrorMessage(conn)))
		C.PQfinish(conn)
		return nil, fmt.Errorf("PostgreSQL connect failed: %s", msg)
	}
	return &pqConn{conn: conn}, nil
}

type pqConn struct {
	mu     sync.Mutex
	conn   *C.PGconn
	closed bool
	inTx   bool
}

var _ driver.Conn = (*pqConn)(nil)
var _ driver.ConnBeginTx = (*pqConn)(nil)
var _ driver.ExecerContext = (*pqConn)(nil)
var _ driver.QueryerContext = (*pqConn)(nil)
var _ driver.Pinger = (*pqConn)(nil)
var _ driver.SessionResetter = (*pqConn)(nil)
var _ driver.Validator = (*pqConn)(nil)

func (c *pqConn) Prepare(query string) (driver.Stmt, error) {
	if strings.TrimSpace(query) == "" {
		return nil, errors.New("empty SQL statement")
	}
	return &pqStmt{conn: c, query: query}, nil
}

func (c *pqConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	C.PQfinish(c.conn)
	c.closed = true
	c.conn = nil
	return nil
}

func (c *pqConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *pqConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureUsableLocked(); err != nil {
		return nil, err
	}
	if c.inTx {
		return nil, errors.New("transaction already active")
	}
	var statement strings.Builder
	statement.WriteString("BEGIN")
	switch opts.Isolation {
	case driver.IsolationLevel(sql.LevelDefault), driver.IsolationLevel(sql.LevelReadCommitted):
	case driver.IsolationLevel(sql.LevelRepeatableRead):
		statement.WriteString(" ISOLATION LEVEL REPEATABLE READ")
	case driver.IsolationLevel(sql.LevelSerializable):
		statement.WriteString(" ISOLATION LEVEL SERIALIZABLE")
	case driver.IsolationLevel(sql.LevelReadUncommitted):
		statement.WriteString(" ISOLATION LEVEL READ COMMITTED")
	default:
		return nil, fmt.Errorf("unsupported transaction isolation level: %d", opts.Isolation)
	}
	if opts.ReadOnly {
		statement.WriteString(" READ ONLY")
	}
	result, err := c.execLocked(statement.String(), nil)
	if result != nil {
		C.PQclear(result)
	}
	if err != nil {
		return nil, err
	}
	c.inTx = true
	return &pqTx{conn: c}, nil
}

func (c *pqConn) Ping(ctx context.Context) error {
	rows, err := c.QueryContext(ctx, "SELECT 1", nil)
	if err != nil {
		return err
	}
	defer rows.Close()
	values := make([]driver.Value, 1)
	if err := rows.Next(values); err != nil {
		return err
	}
	return nil
}

func (c *pqConn) ResetSession(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureUsableLocked(); err != nil {
		return err
	}
	if c.inTx {
		result, err := c.execLocked("ROLLBACK", nil)
		if result != nil {
			C.PQclear(result)
		}
		c.inTx = false
		return err
	}
	return nil
}

func (c *pqConn) IsValid() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed && c.conn != nil && C.PQstatus(c.conn) == C.CONNECTION_OK
}

func (c *pqConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureUsableLocked(); err != nil {
		return nil, err
	}
	result, err := c.execLocked(query, args)
	if err != nil {
		return nil, err
	}
	defer C.PQclear(result)
	if err := resultStatusError(result); err != nil {
		return nil, err
	}
	affected := int64(0)
	if raw := strings.TrimSpace(C.GoString(C.PQcmdTuples(result))); raw != "" {
		affected, _ = strconv.ParseInt(raw, 10, 64)
	}
	return pqResult{rowsAffected: affected}, nil
}

func (c *pqConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureUsableLocked(); err != nil {
		return nil, err
	}
	result, err := c.execLocked(query, args)
	if err != nil {
		return nil, err
	}
	if err := resultStatusError(result); err != nil {
		C.PQclear(result)
		return nil, err
	}
	if C.PQresultStatus(result) != C.PGRES_TUPLES_OK {
		C.PQclear(result)
		return nil, errors.New("query did not return rows")
	}
	fields := int(C.PQnfields(result))
	columns := make([]string, fields)
	oids := make([]uint32, fields)
	for i := 0; i < fields; i++ {
		columns[i] = C.GoString(C.PQfname(result, C.int(i)))
		oids[i] = uint32(C.PQftype(result, C.int(i)))
	}
	return &pqRows{result: result, columns: columns, oids: oids, rowCount: int(C.PQntuples(result))}, nil
}

func (c *pqConn) ensureUsableLocked() error {
	if c.closed || c.conn == nil {
		return driver.ErrBadConn
	}
	if C.PQstatus(c.conn) != C.CONNECTION_OK {
		return driver.ErrBadConn
	}
	return nil
}

func (c *pqConn) execLocked(query string, args []driver.NamedValue) (*C.PGresult, error) {
	cQuery := C.CString(query)
	defer C.free(unsafe.Pointer(cQuery))
	var result *C.PGresult
	if len(args) == 0 {
		result = C.PQexec(c.conn, cQuery)
	} else {
		ordered, err := orderedArguments(args)
		if err != nil {
			return nil, err
		}
		array := C.malloc(C.size_t(len(ordered)) * C.size_t(unsafe.Sizeof(uintptr(0))))
		if array == nil {
			return nil, errors.New("allocate PostgreSQL parameter array")
		}
		defer C.free(array)
		values := unsafe.Slice((**C.char)(array), len(ordered))
		allocated := make([]unsafe.Pointer, 0, len(ordered))
		for i, arg := range ordered {
			if arg == nil {
				values[i] = nil
				continue
			}
			text, err := parameterText(arg)
			if err != nil {
				for _, item := range allocated {
					C.free(item)
				}
				return nil, err
			}
			ptr := C.CString(text)
			allocated = append(allocated, unsafe.Pointer(ptr))
			values[i] = ptr
		}
		defer func() {
			for _, item := range allocated {
				C.free(item)
			}
		}()
		result = C.PQexecParams(c.conn, cQuery, C.int(len(ordered)), nil, (**C.char)(array), nil, nil, 0)
	}
	if result == nil {
		return nil, fmt.Errorf("PostgreSQL execution returned no result: %s", strings.TrimSpace(C.GoString(C.PQerrorMessage(c.conn))))
	}
	if err := resultStatusError(result); err != nil {
		C.PQclear(result)
		return nil, err
	}
	return result, nil
}

func orderedArguments(args []driver.NamedValue) ([]any, error) {
	ordered := make([]any, len(args))
	for _, arg := range args {
		if arg.Ordinal <= 0 || arg.Ordinal > len(args) {
			return nil, fmt.Errorf("invalid parameter ordinal %d", arg.Ordinal)
		}
		ordered[arg.Ordinal-1] = arg.Value
	}
	return ordered, nil
}

func parameterText(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	case bool:
		return strconv.FormatBool(v), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case int32:
		return strconv.FormatInt(int64(v), 10), nil
	case int:
		return strconv.Itoa(v), nil
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64), nil
	case time.Time:
		return v.UTC().Format(time.RFC3339Nano), nil
	default:
		return "", fmt.Errorf("unsupported PostgreSQL parameter type %T", value)
	}
}

func resultStatusError(result *C.PGresult) error {
	status := C.PQresultStatus(result)
	if status == C.PGRES_COMMAND_OK || status == C.PGRES_TUPLES_OK || status == C.PGRES_EMPTY_QUERY {
		return nil
	}
	message := strings.TrimSpace(C.GoString(C.PQresultErrorMessage(result)))
	state := C.PQresultErrorField(result, C.PG_DIAG_SQLSTATE)
	if state != nil {
		code := C.GoString(state)
		if code != "" {
			return fmt.Errorf("%s (SQLSTATE %s)", message, code)
		}
	}
	if message == "" {
		message = "PostgreSQL command failed"
	}
	return errors.New(message)
}

type pqStmt struct {
	conn  *pqConn
	query string
}

func (s *pqStmt) Close() error  { return nil }
func (s *pqStmt) NumInput() int { return -1 }
func (s *pqStmt) Exec(args []driver.Value) (driver.Result, error) {
	named := make([]driver.NamedValue, len(args))
	for i, value := range args {
		named[i] = driver.NamedValue{Ordinal: i + 1, Value: value}
	}
	return s.conn.ExecContext(context.Background(), s.query, named)
}
func (s *pqStmt) Query(args []driver.Value) (driver.Rows, error) {
	named := make([]driver.NamedValue, len(args))
	for i, value := range args {
		named[i] = driver.NamedValue{Ordinal: i + 1, Value: value}
	}
	return s.conn.QueryContext(context.Background(), s.query, named)
}

type pqTx struct{ conn *pqConn }

func (tx *pqTx) Commit() error   { return tx.finish("COMMIT") }
func (tx *pqTx) Rollback() error { return tx.finish("ROLLBACK") }
func (tx *pqTx) finish(command string) error {
	tx.conn.mu.Lock()
	defer tx.conn.mu.Unlock()
	if !tx.conn.inTx {
		return errors.New("transaction is not active")
	}
	result, err := tx.conn.execLocked(command, nil)
	if result != nil {
		C.PQclear(result)
	}
	tx.conn.inTx = false
	return err
}

type pqResult struct{ rowsAffected int64 }

func (r pqResult) LastInsertId() (int64, error) {
	return 0, errors.New("LastInsertId is not supported by PostgreSQL")
}
func (r pqResult) RowsAffected() (int64, error) { return r.rowsAffected, nil }

type pqRows struct {
	result   *C.PGresult
	columns  []string
	oids     []uint32
	row      int
	rowCount int
	closed   bool
}

func (r *pqRows) Columns() []string { return r.columns }
func (r *pqRows) Close() error {
	if !r.closed && r.result != nil {
		C.PQclear(r.result)
		r.closed = true
		r.result = nil
	}
	return nil
}
func (r *pqRows) Next(dest []driver.Value) error {
	if r.closed || r.row >= r.rowCount {
		return io.EOF
	}
	for col := range r.columns {
		if C.PQgetisnull(r.result, C.int(r.row), C.int(col)) != 0 {
			dest[col] = nil
			continue
		}
		raw := C.GoString(C.PQgetvalue(r.result, C.int(r.row), C.int(col)))
		value, err := decodeColumn(r.oids[col], raw)
		if err != nil {
			return fmt.Errorf("decode column %s: %w", r.columns[col], err)
		}
		dest[col] = value
	}
	r.row++
	return nil
}

func decodeColumn(oid uint32, raw string) (driver.Value, error) {
	switch oid {
	case 16:
		return raw == "t" || strings.EqualFold(raw, "true"), nil
	case 20, 21, 23:
		return strconv.ParseInt(raw, 10, 64)
	case 700, 701:
		return strconv.ParseFloat(raw, 64)
	case 1114, 1184:
		return parsePostgresTime(raw)
	case 17:
		if strings.HasPrefix(raw, `\x`) {
			return hex.DecodeString(strings.TrimPrefix(raw, `\x`))
		}
		return []byte(raw), nil
	case 114, 3802:
		return []byte(raw), nil
	default:
		return raw, nil
	}
}

func parsePostgresTime(raw string) (time.Time, error) {
	layouts := []string{
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05.999999999-07",
		"2006-01-02 15:04:05.999999999",
		time.RFC3339Nano,
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported PostgreSQL timestamp %q", raw)
}
