const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const state = {
  token: sessionStorage.getItem('platformInstallerToken') || '',
  connected: false,
  locale: sessionStorage.getItem('platformInstallerLocale') || 'en',
  page: 'overview',
  profiles: [],
  integrations: {},
  status: null,
  health: null,
  plan: null,
  plannedRequest: null,
  drRuns: [],
  lifecycleBackups: [],
  lifecycleRuns: [],
  bundle: null,
  preflight: null,
  fieldEvidence: null,
  fieldDiagnostics: null,
  accessSecurity: null,
  sshTrust: null,
  requests: new Map(),
  connectionFailures: 0
};

const pageCopy = {
  overview: ['Overview', 'Connect with the one-time bootstrap token to inspect or operate this appliance.'],
  installation: ['Installation', 'Create a validated request and review every blocker before execution.'],
  progress: ['Progress', 'Follow health-gated execution and resume only from a failed run.'],
  health: ['Platform health', 'Inspect GitOps, HA and air-gap evidence reported by the installer.'],
  recovery: ['Disaster recovery', 'Create and restore only verified off-node appliance backups.'],
  lifecycle: ['Service lifecycle', 'Back up, restore and digest-upgrade managed platform services.']
};
const faPageCopy = {
  overview: ['نمای کلی', 'با توکن راه‌اندازی به نصب‌کننده متصل شوید و وضعیت واقعی را مشاهده کنید.'],
  installation: ['نصب', 'درخواست معتبر بسازید و پیش از اجرا همهٔ خطاها و هشدارها را بررسی کنید.'],
  progress: ['پیشرفت اجرا', 'اجرای مرحله‌ای را مشاهده و فقط از مرحلهٔ ناموفق ادامه دهید.'],
  health: ['سلامت پلتفرم', 'شواهد واقعی GitOps، کلاستر HA و بستهٔ Air-gap را بررسی کنید.'],
  recovery: ['بازیابی بحران', 'فقط نسخه‌های پشتیبان تأییدشده و خارج از نود را ایجاد یا بازیابی کنید.'],
  lifecycle: ['چرخهٔ عمر سرویس‌ها', 'از سرویس‌های مدیریت‌شده نسخهٔ پشتیبان بگیرید، آن‌ها را بازیابی کنید یا ارتقای قفل‌شده به هش انجام دهید.']
};
const faNav = ['نمای کلی','نصب','پیشرفت','سلامت پلتفرم','بازیابی بحران','چرخهٔ عمر سرویس‌ها'];
const enNav = ['Overview','Installation','Progress','Platform health','Disaster recovery','Service lifecycle'];

const faLiteral = {
  "Platform Factory": "کارخانه پلتفرم",
  "Appliance installer": "نصب‌کننده پلتفرم",
  "Overview": "نمای کلی",
  "Installation": "نصب",
  "Progress": "پیشرفت",
  "Platform health": "سلامت پلتفرم",
  "Installer access security": "امنیت دسترسی نصب‌کننده",
  "Transport protection, certificate lifetime and bootstrap-token fingerprint.": "حفاظت انتقال، عمر گواهی و اثرانگشت توکن راه‌اندازی.",
  "Connect to inspect installer access.": "برای مشاهده امنیت دسترسی نصب‌کننده متصل شوید.",
  "Disaster recovery": "بازیابی بحران",
  "Service lifecycle": "چرخه عمر سرویس‌ها",
  "Not connected": "متصل نیست",
  "Connected": "متصل",
  "Connect": "اتصال",
  "Reconnect": "اتصال مجدد",
  "Safe bootstrap workflow": "مسیر امن راه‌اندازی",
  "Plan first. Execute only an approved, executable plan.": "ابتدا برنامه بسازید؛ فقط برنامهٔ تأییدشده و قابل‌اجرا را اجرا کنید.",
  "The installer validates the digest-locked bundle, host topology, connectivity, TLS, managed services, off-node backup and runtime prerequisites before it allows mutation.": "نصب‌کننده پیش از هر تغییر، بستهٔ قفل‌شده به هش، توپولوژی میزبان، ارتباط، TLS، سرویس‌های مدیریت‌شده، نسخهٔ پشتیبان خارج از نود و پیش‌نیازهای زمان اجرا را اعتبارسنجی می‌کند.",
  "NOT STARTED": "شروع نشده",
  "Execution": "اجرا",
  "Unknown": "نامشخص",
  "Connect to inspect policy": "برای مشاهده سیاست متصل شوید",
  "Profile": "پروفایل",
  "No installation request": "درخواست نصبی وجود ندارد",
  "No steps executed": "هیچ مرحله‌ای اجرا نشده است",
  "Evidence": "شواهد",
  "Pending": "در انتظار",
  "Runtime verification not complete": "بررسی سلامت اجرا کامل نشده است",
  "Next action": "اقدام بعدی",
  "Derived from current runtime state; no demo data is shown.": "این اطلاعات از وضعیت واقعی سیستم خوانده می‌شود و دادهٔ نمونه یا ساختگی نمایش داده نمی‌شود.",
  "Connect with the bootstrap token.": "با توکن راه‌اندازی متصل شوید.",
  "Current run": "اجرای فعلی",
  "Immutable identifiers and latest failure, when present.": "شناسه‌های ثابت اجرای نصب و آخرین خطا، در صورت وجود.",
  "No installation run loaded.": "هیچ اجرای نصبی بارگذاری نشده است.",
  "Installation request": "درخواست نصب",
  "All values are explicit. Credentials are accepted only as secret references, except the dedicated SSH-key vault action.": "همهٔ مقادیر باید مشخص باشند. اطلاعات محرمانه فقط با مرجع امن پذیرفته می‌شود؛ کلید SSH نیز فقط از مسیر اختصاصی ذخیرهٔ امن وارد می‌شود.",
  "1. Deployment profile": "۱. پروفایل استقرار",
  "Load the product-supported profiles after connecting.": "پس از اتصال، پروفایل‌های پشتیبانی‌شده محصول بارگذاری می‌شوند.",
  "Connect to load profiles": "برای بارگذاری پروفایل‌ها متصل شوید",
  "Connectivity": "نوع اتصال",
  "Restricted egress": "خروجی شبکه محدود",
  "Disconnected / air-gap": "قطع از شبکه / Air-gap",
  "Infrastructure": "زیرساخت",
  "Existing Linux hosts": "سرورهای Linux موجود",
  "Existing Kubernetes cluster": "کلاستر Kubernetes موجود",
  "No profile selected.": "پروفایلی انتخاب نشده است.",
  "2. Infrastructure and access": "۲. زیرساخت و دسترسی",
  "The selected profile controls the required node count and HA topology.": "پروفایل انتخاب‌شده تعداد نود و توپولوژی HA موردنیاز را تعیین می‌کند.",
  "Management nodes": "نودهای مدیریت",
  "Management access nodes": "نشانی‌های دسترسی نودهای مدیریت",
  "Use exactly three nodes for Production Standard HA.": "برای Production Standard HA دقیقاً سه نود استفاده کنید.",
  "Use exactly three access addresses for Production Standard HA.": "برای Production Standard HA دقیقاً سه نشانی دسترسی وارد کنید.",
  "HA east-west addresses": "نشانی‌های داخلی east-west برای HA",
  "Use this when SSH/public access and RKE2/etcd traffic use different NICs. The installer never assigns these IPs.": "وقتی دسترسی SSH/عمومی و ترافیک RKE2/etcd از کارت شبکه‌های متفاوت عبور می‌کنند، این نشانی‌ها را وارد کنید. نصب‌کننده هرگز این IPها را تنظیم نمی‌کند.",
  "HA interface": "کارت شبکه داخلی HA",
  "If set, every east-west IP must already exist on this interface.": "در صورت تعیین، همه IPهای داخلی باید از قبل روی همین کارت شبکه تنظیم شده باشند.",
  "Credential reference": "مرجع اطلاعات دسترسی",
  "Never paste a password or token.": "هرگز رمز عبور یا توکن خام وارد نکنید.",
  "SSH user": "کاربر SSH",
  "Storage class": "StorageClass",
  "Dedicated HA data devices": "دیسک‌های داده اختصاصی HA",
  "The same whole-disk paths must exist on every HA node. root disks, partitions, mounted disks and disks with foreign signatures are rejected.": "همان مسیرهای دیسک کامل باید روی همه نودهای HA وجود داشته باشند. دیسک سیستم، پارتیشن، دیسک mount شده و دیسک دارای امضای ناشناخته رد می‌شود.",
  "Storage device action": "عملیات دیسک داده",
  "Format empty devices and bind to Longhorn": "فرمت دیسک‌های خالی و اتصال به Longhorn",
  "Only explicitly listed empty disks are formatted. 4SO-owned ext4 disks are resume-safe.": "فقط دیسک‌های خالی که صریحاً وارد شده‌اند فرمت می‌شوند. دیسک فایل‌سیستم اختصاصی متعلق به 4SO در ادامهٔ نصب قابل استفادهٔ مجدد است.",
  "Region": "Region",
  "Store SSH private key securely": "ذخیره امن کلید خصوصی SSH",
  "Pin HA host keys": "تأیید کلید میزبان‌های HA",
  "Rotate pinned host key": "چرخش کلید تأییدشده میزبان",
  "Rotate pinned HA host key": "چرخش کلید تأییدشده میزبان HA",
  "Confirm the exact currently trusted SHA256 fingerprint set, then submit the complete replacement known_hosts trust store. Trust for every non-target peer must remain unchanged.": "مجموعه دقیق اثرانگشت‌های SHA256 فعلی را تأیید کنید، سپس کل مخزن جایگزین known_hosts را ارسال کنید. اعتماد هیچ میزبان دیگری نباید تغییر کند.",
  "Target host": "میزبان هدف",
  "Expected current SHA256 fingerprints": "اثرانگشت‌های SHA256 فعلی مورد انتظار",
  "Copy the currently displayed fingerprint or fingerprints for this host. One per line.": "اثرانگشت یا اثرانگشت‌های فعلی همین میزبان را از وضعیت نمایش‌داده‌شده کپی کنید؛ هر کدام در یک خط.",
  "Complete replacement known_hosts": "مخزن کامل جایگزین known_hosts",
  "Include all currently trusted peers. Only the target host key may change.": "همه میزبان‌های مورداعتماد فعلی را وارد کنید؛ فقط کلید میزبان هدف مجاز به تغییر است.",
  "HA SSH trust has not been checked.": "کلیدهای SSH سرورهای HA هنوز تأیید نشده‌اند.",
  "Paste trusted OpenSSH known_hosts entries for the remote HA peers. The installer stores only public host keys and shows their SHA256 fingerprints.": "کلیدهای عمومی مورداعتماد سرورهای HA را در قالب OpenSSH known_hosts وارد کنید. نصب‌کننده فقط کلید عمومی را ذخیره می‌کند و اثرانگشت SHA256 آن را نشان می‌دهد.",
  "Trusted known_hosts entries": "ورودی‌های مورداعتماد known_hosts",
  "Use explicit peer IPs or hostnames. Hashed entries, wildcards and unknown key types are rejected.": "IP یا نام دقیق هر سرور را وارد کنید. ورودی‌های hash‌شده، wildcard و نوع کلید ناشناخته پذیرفته نمی‌شوند.",
  "Store pinned host keys": "ذخیره کلیدهای تأییدشده",
  "3. Endpoint and TLS": "۳. نشانی سرویس و TLS",
  "The final product endpoint must use HTTPS.": "نشانی نهایی پلتفرم باید با HTTPS در دسترس باشد.",
  "Public endpoint": "نشانی عمومی",
  "DNS zone": "زون DNS",
  "TLS mode": "حالت TLS",
  "Managed ACME": "ACME مدیریت‌شده",
  "Managed private CA": "CA خصوصی مدیریت‌شده",
  "Bootstrap self-signed": "گواهی موقت خودامضا",
  "External certificate": "گواهی خارجی",
  "Certificate secret reference": "مرجع امن گواهی",
  "Bootstrap administrator email": "ایمیل مدیر راه‌اندازی",
  "4. Platform services": "۴. سرویس‌های پلتفرم",
  "Managed services are the safe default. External modes expose only the fields required by the selected adapter.": "سرویس‌های مدیریت‌شده انتخاب پیشنهادی و امن هستند. در حالت خارجی فقط تنظیمات لازم برای همان اتصال نمایش داده می‌شود.",
  "I reviewed the generated warnings, blockers and rollback boundaries and accept the declared installation risk when required by the profile.": "هشدارها، موانع و محدودیت‌های بازگشت را بررسی کرده‌ام و در صورت نیاز پروفایل، ریسک‌های اعلام‌شدهٔ نصب را می‌پذیرم.",
  "Validate and create plan": "اعتبارسنجی و ساخت برنامه",
  "Clear request": "پاک‌کردن درخواست",
  "Validated plan": "برنامه اعتبارسنجی‌شده",
  "NOT VALIDATED": "اعتبارسنجی نشده",
  "Execution sequence": "ترتیب اجرا",
  "Customer actions": "اقدامات مشتری",
  "Authority": "مرجع کنترل",
  "Start installation": "شروع نصب",
  "Download bootstrap CA": "دانلود CA راه‌اندازی",
  "Execution progress": "پیشرفت اجرا",
  "Every step is resumable and health-gated. A failed run resumes from the failed or pending step.": "هر مرحله قابل ادامه است و فقط پس از بررسی سلامت مرحلهٔ قبل جلو می‌رود. در صورت خطا، نصب از همان مرحلهٔ ناموفق یا در انتظار ادامه پیدا می‌کند.",
  "Resume failed run": "ادامه اجرای ناموفق",
  "Reset and clean reinstall": "بازنشانی و نصب پاک",
  "Explicitly uninstall only product-owned RKE2 and generated installer state. Installer access token and pinned HA SSH trust are preserved so a clean reinstall can be planned after reset.": "فقط RKE2 متعلق به محصول و فایل‌های ایجادشده توسط نصب‌کننده حذف می‌شوند. توکن دسترسی نصب‌کننده و کلیدهای SSH تأییدشدهٔ سرورهای HA حفظ می‌شود تا پس از بازنشانی نصب پاک دوباره برنامه‌ریزی شود.",
  "Reset installation": "بازنشانی نصب",
  "Resume interrupted reset": "ادامه بازنشانی قطع‌شده",
  "No reset run exists.": "هیچ اجرای بازنشانی وجود ندارد.",
  "No run loaded.": "اجرایی بارگذاری نشده است.",
  "These cards are sourced from installer runtime evidence, not placeholder metrics.": "این کارت‌ها از شواهد واقعی نصب‌کننده ساخته می‌شوند و هیچ شاخص ساختگی نمایش داده نمی‌شود.",
  "Refresh": "بازخوانی",
  "GitOps handover": "تحویل GitOps",
  "Desired-state publication and reconciliation.": "انتشار وضعیت مطلوب و همگام‌سازی GitOps.",
  "Management HA": "HA مدیریت",
  "Node readiness and quorum evidence.": "وضعیت آمادگی نودها و quorum کلاستر.",
  "Air-gap bundle": "بستهٔ نصب آفلاین",
  "Local artifact and image completeness.": "کامل‌بودن فایل‌ها و imageهای موردنیاز در محیط آفلاین.",
  "Off-node disaster recovery": "بازیابی بحران خارج از نود",
  "Backup PostgreSQL authority, Forgejo repositories and zot blobs to the configured S3-compatible destination.": "از دادهٔ مرجع PostgreSQL، مخزن‌های Forgejo و داده‌های zot در مقصد S3-compatible پیکربندی‌شده نسخهٔ پشتیبان بگیرید.",
  "Create appliance backup": "ساخت نسخهٔ پشتیبان پلتفرم",
  "Available restore points": "نقاط بازیابی موجود",
  "Only completed backups are selectable.": "فقط نسخه‌های پشتیبان کامل‌شده قابل انتخاب هستند.",
  "Recovery runs": "اجراهای بازیابی",
  "Recent backup and restore operations.": "آخرین عملیات پشتیبان‌گیری و بازیابی.",
  "Managed service lifecycle": "چرخه عمر سرویس‌های مدیریت‌شده",
  "Backup, restore and digest-pinned upgrade for Forgejo, zot and Keycloak.": "پشتیبان‌گیری، بازیابی و ارتقای نسخه‌قفل‌شده برای Forgejo، zot و Keycloak.",
  "Service": "سرویس",
  "Forgejo Git": "Git مبتنی بر Forgejo",
  "zot Registry": "Registry مبتنی بر zot",
  "Keycloak Identity": "Identity مبتنی بر Keycloak",
  "Upgrade image": "تصویر ارتقا",
  "Mutable tags are rejected by the backend.": "برچسب قابل‌تغییر در سمت سرور رد می‌شود.",
  "Create service backup": "ساخت نسخهٔ پشتیبان سرویس",
  "Backup and upgrade": "پشتیبان‌گیری و ارتقا",
  "Service backups": "نسخه‌های پشتیبان سرویس",
  "Select an existing verified backup to restore.": "یک نسخهٔ پشتیبان موجود و تأییدشده را برای بازیابی انتخاب کنید.",
  "Lifecycle runs": "اجراهای چرخه عمر",
  "Recent actions for all managed services.": "آخرین اقدامات تمام سرویس‌های مدیریت‌شده.",
  "Connect to installer": "اتصال به نصب‌کننده",
  "The token is retained only for this browser tab.": "توکن فقط در همین زبانهٔ مرورگر نگه داشته می‌شود.",
  "Bootstrap token": "توکن راه‌اندازی",
  "Store HA SSH key": "ذخیره کلید SSH مربوط به HA",
  "The private key is validated, stored mode 0600 and never returned by the API.": "کلید خصوصی اعتبارسنجی می‌شود، با مجوز 0600 ذخیره می‌شود و هرگز از API بازگردانده نمی‌شود.",
  "OpenSSH private key": "کلید خصوصی OpenSSH",
  "Store key": "ذخیره کلید",
  "Confirm action": "تأیید عملیات",
  "Confirmation": "تأیید",
  "Cancel": "انصراف",
  "Confirm": "تأیید",
  "No runtime evidence is available yet.": "هنوز شواهد زمان اجرا موجود نیست.",
  "No persisted installation request": "درخواست نصب ذخیره‌شده‌ای وجود ندارد",
  "Create a validated plan": "ساخت برنامه اعتبارسنجی‌شده",
  "Open Installation, provide real environment values and resolve every blocker.": "بخش نصب را باز کنید، مقادیر واقعی محیط را وارد و همهٔ بلاکرها را رفع کنید.",
  "Open installation": "بازکردن نصب",
  "No installation run exists.": "اجرای نصبی وجود ندارد.",
  "Simulation runtime": "زمان اجرای شبیه‌سازی‌شده",
  "Host runtime": "زمان اجرای واقعی میزبان",
  "Execution in progress": "اجرا در حال انجام است",
  "Verified": "تأییدشده",
  "Authenticated persistence restart check passed": "بررسی احراز‌شدهٔ راه‌اندازی مجدد و ماندگاری داده موفق بود",
  "Final runtime verification has not passed": "تأیید نهایی زمان اجرا هنوز موفق نشده است",
  "State": "وضعیت",
  "Restore": "Restore",
  "No completed appliance backup exists.": "نسخهٔ پشتیبان کامل‌شده‌ای برای پلتفرم وجود ندارد.",
  "No disaster-recovery run exists.": "اجرای بازیابی بحران وجود ندارد.",
  "No backup exists for this service.": "برای این سرویس نسخهٔ پشتیبان موجود نیست.",
  "No lifecycle run exists.": "اجرای چرخه عمر وجود ندارد.",
  "Create backup": "ساخت نسخهٔ پشتیبان",
  "Start restore": "شروع بازیابی",
  "Resume": "ادامه",
  "Backup accepted.": "درخواست پشتیبان‌گیری پذیرفته شد.",
  "Restore accepted.": "درخواست بازیابی پذیرفته شد.",
  "Service backup accepted.": "درخواست پشتیبان‌گیری سرویس پذیرفته شد.",
  "Service restore accepted.": "درخواست بازیابی سرویس پذیرفته شد.",
  "Upgrade accepted.": "ارتقا پذیرفته شد.",
  "Connected to installer.": "اتصال به نصب‌کننده برقرار شد.",
  "SSH private key stored securely.": "کلید خصوصی SSH به‌صورت امن ذخیره شد.",
  "Execution is disabled. Planning and evidence inspection remain available; host mutation cannot start.": "اجرا غیرفعال است. برنامه‌ریزی و مشاهدهٔ شواهد در دسترس‌اند، اما تغییری روی میزبان آغاز نمی‌شود.",
  "Run host preflight": "اجرای پیش‌بررسی میزبان",
  "Host preflight": "پیش‌بررسی میزبان",
  "Read-only checks run before approval and are repeated by Start and Resume.": "بررسی‌های فقط‌خواندنی پیش از تأیید اجرا می‌شوند و در شروع و ادامه دوباره تکرار می‌شوند.",
  "Field execution evidence": "شواهد اجرای میدانی",
  "Bundle, preflight, installation, GitOps, HA, air-gap, lifecycle and DR snapshots bound by one digest.": "تصویرهای وضعیتِ بسته، پیش‌بررسی، نصب، GitOps، HA، نصب آفلاین، چرخهٔ عمر و DR با یک هش مشترک به هم متصل می‌شوند.",
  "Download report": "دریافت گزارش",
  "Verify evidence": "اعتبارسنجی شواهد",
  "A report becomes available after an installation run exists.": "پس از ایجاد اجرای نصب، گزارش در دسترس قرار می‌گیرد.",
  "Failure diagnostics": "عیب‌یابی خطای اجرا",
  "Capture a verified, tamper-evident snapshot of the failed step and every related runtime authority before changing the environment.": "پیش از تغییر محیط، یک تصویر وضعیت تأییدشده و قابل تشخیص دست‌کاری از مرحلهٔ ناموفق و همهٔ مراجع مرتبط زمان اجرا ثبت کنید.",
  "Download diagnostics": "دریافت گزارش عیب‌یابی",
  "Verify diagnostics": "اعتبارسنجی گزارش عیب‌یابی",
  "Diagnostics become available after an installation run exists.": "پس از ایجاد اجرای نصب، گزارش عیب‌یابی در دسترس قرار می‌گیرد.",
  "Plan only": "فقط برنامه‌ریزی",
  "Host mutation may start after approval": "تغییر میزبان پس از تأیید می‌تواند آغاز شود",
  "Execution environment variable is disabled": "متغیر محیطی اجرا غیرفعال است",
  "No additional customer action.": "اقدام دیگری از سمت مشتری لازم نیست.",
  "No blockers remain. Review the sequence and execution policy before starting.": "بلاکِری باقی نمانده است. پیش از شروع، ترتیب اجرا و سیاست اجرایی را بررسی کنید.",
  "BLOCKED": "مسدود",
  "EXECUTION READY": "آماده اجرا"
};
const originalLiteralText = new WeakMap();
const originalLiteralAttributes = new WeakMap();
let localizationBusy = false;
function localizedLiteral(value) {
  const trimmed = String(value || '').trim();
  if (faLiteral[trimmed]) return faLiteral[trimmed];
  let match = trimmed.match(/^Version (.+)$/); if (match) return `نسخه ${match[1]}`;
  match = trimmed.match(/^Last updated (.+)$/); if (match) return `آخرین بروزرسانی ${match[1]}`;
  match = trimmed.match(/^(\d+) files$/); if (match) return `${match[1]} فایل`;
  return '';
}
function skipLiteralNode(node) {
  const parent = node.nodeType === Node.TEXT_NODE ? node.parentElement : node;
  return !parent || Boolean(parent.closest('script,style,pre,code,.technical,[data-no-translate]'));
}
function localizeTree(root = document.body) {
  if (!root || localizationBusy) return;
  localizationBusy = true;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = []; while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const node of nodes) {
    if (skipLiteralNode(node)) continue;
    if (state.locale === 'fa') {
      const translated = localizedLiteral(node.nodeValue);
      if (!translated || translated === node.nodeValue.trim()) continue;
      originalLiteralText.set(node, node.nodeValue);
      const leading = node.nodeValue.match(/^\s*/)?.[0] || '', trailing = node.nodeValue.match(/\s*$/)?.[0] || '';
      node.nodeValue = leading + translated + trailing;
    } else if (originalLiteralText.has(node)) { node.nodeValue = originalLiteralText.get(node); originalLiteralText.delete(node); }
  }
  for (const element of root.querySelectorAll ? root.querySelectorAll('[placeholder],[title],[aria-label]') : []) {
    if (skipLiteralNode(element)) continue;
    const saved = originalLiteralAttributes.get(element) || {};
    for (const attribute of ['placeholder','title','aria-label']) {
      if (!element.hasAttribute(attribute)) continue;
      if (state.locale === 'fa') {
        const current = element.getAttribute(attribute), translated = localizedLiteral(current);
        if (translated && translated !== String(current).trim()) { saved[attribute] = current; element.setAttribute(attribute, translated); }
      } else if (saved[attribute] !== undefined) { element.setAttribute(attribute, saved[attribute]); delete saved[attribute]; }
    }
    originalLiteralAttributes.set(element, saved);
  }
  localizationBusy = false;
}
let localizationScheduled = false;
const localizationObserver = new MutationObserver(() => {
  if (localizationBusy || state.locale !== 'fa' || localizationScheduled) return;
  localizationScheduled = true;
  requestAnimationFrame(() => { localizationScheduled = false; localizeTree(document.body); });
});
localizationObserver.observe(document.body, {subtree:true,childList:true,characterData:true});

function esc(value) {
  return String(value ?? '').replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
}
function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat(state.locale === 'fa' ? 'fa-IR' : 'en-GB', {dateStyle:'medium',timeStyle:'short'}).format(date);
}
function shortDigest(value) {
  if (!value) return '—';
  const raw = String(value);
  return raw.length > 28 ? `${raw.slice(0,18)}…${raw.slice(-8)}` : raw;
}
function stateClass(value) {
  const v = String(value || '').toUpperCase();
  if (['SUCCEEDED','READY','ACTIVE','HEALTHY','ONLINE','COMPLETE','VERIFIED','PASS'].some(x => v.includes(x))) return 'success';
  if (['FAILED','ERROR','OFFLINE','BLOCKED','DEGRADED'].some(x => v.includes(x))) return 'failed';
  if (['RUNNING','QUEUED','PENDING','WAITING','NOT_STARTED'].some(x => v.includes(x))) return 'warning';
  return 'neutral';
}
function pill(value) { return `<span class="state-pill ${stateClass(value)}">${esc(value || 'UNKNOWN')}</span>`; }
function toast(message, kind = 'success') {
  const node = document.createElement('div');
  node.className = `toast ${kind}`;node.setAttribute('role',kind==='error'?'alert':'status');
  node.innerHTML=`<span>${esc(message)}</span><button type="button" class="toast-close icon-button" aria-label="Close"><svg aria-hidden="true" class="control-icon"><use href="#icon-close"></use></svg></button>`;
  node.querySelector('button').onclick=()=>node.remove();$('#toast-region').append(node);
  if(kind!=='error')setTimeout(() => node.remove(), 5200);
}
function errorMessage(payload, fallback) {
  if (!payload) return fallback;
  if (typeof payload === 'string') return payload;
  return payload.message || payload.error?.message || payload.error || fallback;
}
async function api(path, options = {}) {
  if (!state.token) throw new Error('Bootstrap token is required.');
  const headers = new Headers(options.headers || {});
  headers.set('Authorization', `Bearer ${state.token}`);
  let body = options.body;
  if (body !== undefined) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(body);
  }
  const response = await fetch(path, {...options, headers, body});
  const type = response.headers.get('content-type') || '';
  const payload = type.includes('json') ? await response.json().catch(() => null) : await response.text();
  if (!response.ok) {
    if (response.status === 401) disconnect(false);
    throw new Error(errorMessage(payload, `${response.status} ${response.statusText}`));
  }
  return payload;
}
function setConnection(connected) {
  state.connected = connected;
  $('#connection-dot').className = `dot ${connected ? 'online' : 'offline'}`;
  $('#connection-label').textContent = connected ? 'Connected' : 'Not connected';
  $('#connect-button').textContent = connected ? 'Reconnect' : 'Connect';
}
function disconnect(clear = true) {
  if (clear) {
    state.token = '';
    sessionStorage.removeItem('platformInstallerToken');
  }
  setConnection(false);
}
function applyLocale() {
  document.documentElement.lang = state.locale;
  document.documentElement.dir = state.locale === 'fa' ? 'rtl' : 'ltr';
  $('#language-toggle').textContent = state.locale === 'fa' ? 'EN' : 'فا';
  $$('#nav button b').forEach((node,index) => node.textContent = (state.locale === 'fa' ? faNav : enNav)[index]);
  updatePageHeader();
  localizeTree(document.body);
}
function updatePageHeader() {
  const copy = (state.locale === 'fa' ? faPageCopy : pageCopy)[state.page];
  $('#page-title').textContent = copy[0];
  $('#page-subtitle').textContent = copy[1];
}
function installerNavFocusable(){ return $$('#sidebar button:not([disabled]), #sidebar a[href], #sidebar [tabindex]:not([tabindex="-1"])').filter(node=>!node.hidden); }
function syncInstallerMenuAccessibility(open = $('#sidebar').classList.contains('open')){
  const sidebar=$('#sidebar'),mobile=window.matchMedia('(max-width: 800px)').matches;
  sidebar.inert=mobile&&!open;sidebar.setAttribute('aria-hidden',mobile&&!open?'true':'false');
}
function setInstallerMenu(open){
  const sidebar=$('#sidebar'),toggle=$('#menu-toggle'),scrim=$('#nav-scrim');
  sidebar.classList.toggle('open',open);
  toggle.setAttribute('aria-expanded',open?'true':'false');
  scrim.hidden=!open;
  document.body.classList.toggle('nav-open',open);
  syncInstallerMenuAccessibility(open);
  if(open){const active=$('#nav button.active')||installerNavFocusable()[0];active?.focus();}
}
window.addEventListener('resize',()=>syncInstallerMenuAccessibility());
function navigate(page) {
  state.page = page;
  $$('.page').forEach(node => node.classList.toggle('active', node.id === page));
  $$('#nav button').forEach(node => { const active=node.dataset.page===page; node.classList.toggle('active',active); if(active)node.setAttribute('aria-current','page'); else node.removeAttribute('aria-current'); });
  setInstallerMenu(false);
  updatePageHeader();
  if (!state.connected) return;
  if (page === 'health') refreshHealth();
  if (page === 'recovery') refreshDR();
  if (page === 'lifecycle') refreshLifecycle();
}
$('#nav').onclick = event => { const button = event.target.closest('[data-page]'); if (button) navigate(button.dataset.page); };
$('#menu-toggle').onclick = () => setInstallerMenu(!$('#sidebar').classList.contains('open'));
$('#nav-scrim').onclick = () => { setInstallerMenu(false); $('#menu-toggle').focus(); };
syncInstallerMenuAccessibility(false);
document.addEventListener('keydown',event=>{
  if(!$('#sidebar').classList.contains('open'))return;
  if(event.key==='Escape'){event.preventDefault();setInstallerMenu(false);$('#menu-toggle').focus();return;}
  if(event.key!=='Tab')return;
  const nodes=installerNavFocusable();if(!nodes.length)return;const first=nodes[0],last=nodes[nodes.length-1];
  if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}
  else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}
});
$('#language-toggle').onclick = () => { state.locale = state.locale === 'fa' ? 'en' : 'fa'; sessionStorage.setItem('platformInstallerLocale',state.locale); applyLocale(); };

function detailsHTML(entries) {
  if (!entries.length) return '<div class="empty-state">No runtime evidence is available yet.</div>';
  return entries.map(([label,value]) => `<div class="detail-row"><span>${esc(label)}</span><strong class="${String(value).includes('sha256:') ? 'technical' : ''}">${esc(value)}</strong></div>`).join('');
}
function flatten(object, prefix = '', depth = 0) {
  if (!object || typeof object !== 'object') return [];
  const rows = [];
  for (const [key,value] of Object.entries(object)) {
    const label = prefix ? `${prefix} · ${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value) && depth < 1) rows.push(...flatten(value,label,depth+1));
    else if (Array.isArray(value)) rows.push([label, value.length ? value.map(item => typeof item === 'object' ? item.name || item.id || item.state || 'item' : item).join(', ') : 'None']);
    else rows.push([label, value === true ? 'Yes' : value === false ? 'No' : value ?? '—']);
  }
  return rows;
}

const serviceDefinitions = {
  git: {title:'Git desired state', managed:'forgejo', fields:['url','credentialRef','organization','repository','webhookMode']},
  registry: {title:'OCI registry', managed:'zot', fields:['url','credentialRef']},
  database: {title:'PostgreSQL authority', managed:'cloudnative-pg', fields:['url','credentialRef','region']},
  objectStorage: {title:'Evidence and backup storage', managed:'local-evidence', fields:['url','credentialRef','bucket','prefix','region']},
  identity: {title:'Identity and SSO', managed:'keycloak', fields:['issuerUrl','clientId','credentialRef','adminEmail']}
};
const fieldLabels = {url:'HTTPS endpoint',credentialRef:'Credential reference',organization:'Organization',repository:'Repository',webhookMode:'Webhook mode',region:'Region',bucket:'مخزن S3',prefix:'پیشوند مسیر',issuerUrl:'OIDC issuer URL',clientId:'OIDC client ID',adminEmail:'Bootstrap administrator email'};
function providerFromIntegration(id) { return String(id || '').replace(/^managed-/,'').replace(/^external-/,''); }
function renderServices() {
  $('#service-editor').innerHTML = Object.entries(serviceDefinitions).map(([kind,def]) => {
    const options = state.integrations[kind] || [];
    const choices = options.length ? options.map(item => `<option value="${esc(item.id)}" data-mode="${esc(item.mode)}" ${item.default ? 'selected' : ''}>${esc(item.id.replaceAll('-',' '))}</option>`).join('') : `<option value="managed-${esc(def.managed)}">Managed ${esc(def.managed)}</option>`;
    const fields = def.fields.map(name => `<label data-service-field="${esc(name)}"><span>${esc(fieldLabels[name])}</span><input data-input="${esc(name)}" class="${['url','credentialRef','issuerUrl'].includes(name)?'technical':''}" ${['url','issuerUrl'].includes(name)?'type="url"':''} placeholder="${name === 'credentialRef' ? 'secret:// or external-secret://' : ''}" dir="${['url','credentialRef','issuerUrl'].includes(name)?'ltr':'auto'}"></label>`).join('');
    return `<section class="service-card" data-service="${esc(kind)}"><h3>${esc(def.title)}</h3><label><span>Mode and provider</span><select data-input="integration">${choices}</select></label><div class="external-fields">${fields}</div></section>`;
  }).join('');
  $$('#service-editor [data-input="integration"]').forEach(select => { select.addEventListener('change', syncServiceCard); syncServiceCard({currentTarget:select}); });
}
function syncServiceCard(event) {
  const select = event.currentTarget;
  const card = select.closest('[data-service]');
  const option = select.selectedOptions[0];
  const mode = option?.dataset.mode || (select.value.startsWith('external-') ? 'external' : 'managed-internal');
  const kind = card.dataset.service;
  card.dataset.mode = mode;
  card.querySelectorAll('[data-service-field]').forEach(label => {
    const name = label.dataset.serviceField;
    const always = kind === 'identity' && name === 'adminEmail' && mode !== 'external';
    label.hidden = mode !== 'external' && !always;
    const input = label.querySelector('input');
    input.required = mode === 'external' && ['url','credentialRef'].includes(name);
  });
}
function serviceSpec(kind) {
  const card = $(`[data-service="${kind}"]`);
  const select = card.querySelector('[data-input="integration"]');
  const mode = card.dataset.mode || 'managed-internal';
  const value = name => card.querySelector(`[data-input="${name}"]`)?.value.trim() || '';
  const spec = {mode, provider:providerFromIntegration(select.value)};
  if (mode === 'external') {
    for (const name of serviceDefinitions[kind].fields) if (value(name)) spec[name] = value(name);
  } else if (kind === 'identity' && value('adminEmail')) spec.adminEmail = value('adminEmail');
  return spec;
}
function selectedProfile() { return state.profiles.find(item => item.id === $('#profile').value); }
function syncProfile() {
  const profile = selectedProfile();
  if (!profile) { $('#profile-summary').textContent = 'No profile selected.'; return; }
  const sizing=profile.sizing||{}; const sizingText=sizing.minimumVcpu?`<br>Per ${esc(sizing.scope||'appliance')}: minimum ${esc(sizing.minimumVcpu)} vCPU · ${esc(sizing.minimumMemoryGiB)} GiB RAM · ${esc(sizing.minimumDiskGiB)} GiB disk (${esc(sizing.minimumFreeDiskGiB||0)} GiB free); recommended ${esc(sizing.recommendedVcpu)} vCPU · ${esc(sizing.recommendedMemoryGiB)} GiB RAM · ${esc(sizing.recommendedDiskGiB)} GiB disk.`:''; $('#profile-summary').innerHTML = `<strong>${esc(profile.displayName)}</strong><br>${esc(profile.description)}<br>${profile.production ? 'Production' : 'Evaluation'} · minimum ${esc(profile.minNodes)} node(s) · recommended ${esc(profile.recommendedNodes)}.${sizingText}`;
  const allowed = new Set(profile.supportedConnectivity || []);
  $$('#connectivity option').forEach(option => option.disabled = allowed.size && !allowed.has(option.value));
  if (allowed.size && !allowed.has($('#connectivity').value)) $('#connectivity').value = [...allowed][0];
  if (profile.id === 'evaluation-single-node') $('#tls-mode').value = 'bootstrap-self-signed';
  if (profile.id === 'production-standard-ha') {
    $('#provider').value = 'existing-hosts';
    const objectSelect = $('[data-service="objectStorage"] [data-input="integration"]');
    const external = [...objectSelect.options].find(option => option.dataset.mode === 'external');
    if (external) { objectSelect.value = external.value; syncServiceCard({currentTarget:objectSelect}); }
  }
  syncInfrastructure();
}
function syncInfrastructure() {
  const existingCluster = $('#provider').value === 'existing-kubernetes';
  const haHosts = !existingCluster && selectedProfile()?.id === 'production-standard-ha';
  $('#nodes-field').hidden = existingCluster;
  $('#cluster-nodes-field').hidden = existingCluster;
  $('#cluster-interface-field').hidden = existingCluster;
  $('#storage-devices-field').hidden = !haHosts;
  $('#storage-device-mode-field').hidden = !haHosts;
  $('#ssh-user-field').hidden = existingCluster;
  $('#nodes').required = !existingCluster;
  $('#storage-devices').required = haHosts;
  $('#storage-device-mode').required = haHosts;
  if (existingCluster && $('#credential-ref').value === 'secret://installer/ssh-private-key') $('#credential-ref').value = '';
}
function syncTLS() { $('#certificate-field').hidden = $('#tls-mode').value !== 'external-certificate'; $('#certificate-ref').required = !$('#certificate-field').hidden; }
$('#profile').onchange = syncProfile;
$('#provider').onchange = syncInfrastructure;
$('#tls-mode').onchange = syncTLS;

function buildInstallRequest() {
  const existingCluster = $('#provider').value === 'existing-kubernetes';
  return {
    profileId: $('#profile').value,
    connectivity: $('#connectivity').value,
    infrastructure: {
      provider: $('#provider').value,
      existingCluster,
      nodeAddresses: existingCluster ? [] : $('#nodes').value.split(/\r?\n|,/).map(v=>v.trim()).filter(Boolean),
      clusterNodeAddresses: existingCluster ? [] : $('#cluster-nodes').value.split(/\r?\n|,/).map(v=>v.trim()).filter(Boolean),
      clusterInterface: existingCluster ? '' : $('#cluster-interface').value.trim(),
      credentialRef: $('#credential-ref').value.trim(),
      sshUser: existingCluster ? '' : $('#ssh-user').value.trim(),
      storageClass: $('#storage-class').value.trim(),
      storageDataDevices: existingCluster ? [] : $('#storage-devices').value.split(/\r?\n|,/).map(v=>v.trim()).filter(Boolean),
      storageDeviceMode: existingCluster ? '' : $('#storage-device-mode').value,
      region: $('#region').value.trim()
    },
    network: {
      publicEndpoint: $('#endpoint').value.trim(),
      dnsZone: $('#dns-zone').value.trim(),
      tlsMode: $('#tls-mode').value,
      certificateRef: $('#certificate-ref').value.trim()
    },
    services: {
      git: serviceSpec('git'), registry: serviceSpec('registry'), database: serviceSpec('database'),
      objectStorage: serviceSpec('objectStorage'), identity: serviceSpec('identity')
    },
    acceptRisk: $('#accept-risk').checked
  };
}
function renderPlan(result) {
  const plan = result.plan;
  state.plan = result;
  $('#plan-panel').hidden = false;
  $('#plan-state').className = `state-pill ${plan.executable ? 'success' : 'failed'}`;
  $('#plan-state').textContent = plan.executable ? 'EXECUTION READY' : 'BLOCKED';
  $('#plan-summary').textContent = `${plan.profile.displayName} · ${plan.steps.length} steps · ${plan.blockers.length} blockers · ${plan.warnings.length} warnings`;
  const messages = [];
  if (plan.blockers?.length) messages.push(`<div class="error-box"><strong>Blockers</strong><ul>${plan.blockers.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></div>`);
  if (plan.warnings?.length) messages.push(`<div class="warning-box"><strong>Warnings</strong><ul>${plan.warnings.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></div>`);
  if (!messages.length) messages.push('<div class="success-box">No blockers remain. Review the sequence and execution policy before starting.</div>');
  $('#plan-blockers').innerHTML = messages.join('');
  $('#plan-steps').innerHTML = plan.steps.map(step => `<div class="timeline-item"><span class="timeline-index">${esc(step.order)}</span><div><h4>${esc(step.title)}</h4><p>${esc(step.stage)} · ${esc(step.executor)} · risk ${esc(step.risk)}<br>Rollback: ${esc(step.rollback)}</p></div>${pill(step.risk)}</div>`).join('');
  $('#plan-actions').innerHTML = plan.customerActions?.length ? `<ol>${plan.customerActions.map(item=>`<li>${esc(item)}</li>`).join('')}</ol>` : '<div class="empty-state">No additional customer action.</div>';
  $('#plan-authority').innerHTML = detailsHTML([['Plan ID',plan.id],['Spec digest',plan.specDigest],['Bundle digest',result.bundleDigest || 'Unavailable'],['Authority gate',plan.authorityGate],['Execution policy',result.executionEnabled ? 'Enabled' : 'Disabled']]);
  state.preflight = null;
  $('#preflight-panel').hidden = true;
  $('#start-installation').disabled = true;
  if (plan.executable && !result.executionEnabled) $('#global-alert').innerHTML = 'The plan is executable, but mutation is disabled. Set <span class="technical">PLATFORM_INSTALLER_ALLOW_EXECUTION=true</span> only after plan review.';
  $('#global-alert').hidden = plan.executable ? result.executionEnabled : true;
  $('#plan-panel').scrollIntoView({behavior:'smooth',block:'start'});
}
function renderPreflight(report) {
  state.preflight = report;
  $('#preflight-panel').hidden = false;
  const passed = report?.state === 'PASSED';
  $('#preflight-state').className = `state-pill ${passed ? 'success' : 'failed'}`;
  $('#preflight-state').textContent = report?.state || 'NOT RUN';
  $('#preflight-summary').innerHTML = detailsHTML([
    ['Report ID',report?.id || '—'],['Profile',report?.profileId || '—'],['Execution mode',report?.simulation ? 'SIMULATION' : 'LIVE HOST'],
    ['Request digest',report?.requestDigest || '—'],['Bundle digest',report?.bundleDigest || '—'],['Preflight digest',report?.digest || '—'],['Generated',formatDate(report?.generatedAt)]
  ]);
  const checks = report?.checks || [];
  $('#preflight-checks').innerHTML = checks.length ? checks.map((check,index)=>`<div class="timeline-item ${String(check.state).toLowerCase()}"><span class="timeline-index">${index+1}</span><div><h4>${esc(check.title)}</h4><p>${esc(check.key)}<br>${esc(check.detail)}</p></div>${pill(check.state)}</div>`).join('') : '<div class="empty-state">No preflight checks were returned.</div>';
  const executable = state.plan?.plan?.executable === true && state.plan?.executionEnabled === true;
  $('#start-installation').disabled = !(passed && executable);
}
async function runPreflight() {
  if (!state.plannedRequest) { toast('Create a validated plan first.','error'); return null; }
  try {
    const report = await api('/api/v1/preflight',{method:'POST',body:{installation:state.plannedRequest}});
    renderPreflight(report);
    toast(report.state === 'PASSED' ? 'Host preflight passed.' : 'Host preflight is blocked.', report.state === 'PASSED' ? 'success' : 'error');
    return report;
  } catch (error) { toast(error.message,'error'); return null; }
}
$('#run-preflight').onclick = runPreflight;

$('#installation-form').onsubmit = async event => {
  event.preventDefault();
  if (!event.currentTarget.reportValidity()) return;
  const request = buildInstallRequest();
  const profile = selectedProfile();
  if (profile && request.infrastructure.provider !== 'existing-kubernetes' && request.infrastructure.nodeAddresses.length < profile.minNodes) {
    toast(`The selected profile requires at least ${profile.minNodes} node(s).`,'error'); return;
  }
  if (profile?.id === 'production-standard-ha' && request.infrastructure.clusterNodeAddresses.length && request.infrastructure.clusterNodeAddresses.length !== request.infrastructure.nodeAddresses.length) {
    toast('HA east-west addresses must contain one IP for each management access node.','error'); return;
  }
  if (profile?.id === 'production-standard-ha' && request.infrastructure.clusterInterface && !request.infrastructure.clusterNodeAddresses.length) {
    toast('An HA interface requires explicit east-west addresses; the installer never assigns IPs.','error'); return;
  }
  if (profile?.id === 'production-standard-ha' && !request.infrastructure.storageDataDevices.length) {
    toast('Production Standard HA requires at least one explicit dedicated data disk.','error'); return;
  }
  if (profile?.id === 'production-standard-ha' && request.infrastructure.storageDeviceMode !== 'format-empty') {
    toast('Production Standard HA requires the explicit format-empty storage device action.','error'); return;
  }
  try {
    const result = await api('/api/v1/plan',{method:'POST',body:{installation:request}});
    state.plannedRequest = request;
    renderPlan(result);
    toast('Installation plan validated.');
    if (result.plan?.executable) await runPreflight();
  } catch (error) { toast(error.message,'error'); }
};
$('#installation-form').onreset = () => setTimeout(() => { state.plan=null; state.plannedRequest=null; state.preflight=null; $('#plan-panel').hidden=true; $('#preflight-panel').hidden=true; renderServices(); syncProfile(); syncTLS(); },0);

function confirmAction({title,message,phrase = '',button = 'Confirm'}) {
  return new Promise(resolve => {
    $('#confirm-title').textContent = title;
    $('#confirm-message').textContent = message;
    $('#confirm-action').textContent = button;
    $('#confirm-input-field').hidden = !phrase;
    $('#confirm-input-label').textContent = phrase ? `Type ${phrase} to continue` : 'Confirmation';
    $('#confirm-input').value = '';
    const dialog = $('#confirm-dialog');
    const finish = value => { dialog.close(); resolve(value); };
    $('#confirm-action').onclick = () => {
      if (phrase && $('#confirm-input').value.trim() !== phrase) { toast(`Type ${phrase} exactly.`,'error'); return; }
      finish(true);
    };
    dialog.addEventListener('close',()=>resolve(false),{once:true});
    dialog.showModal();
  });
}
$('#start-installation').onclick = async () => {
  if (!state.plannedRequest || !state.plan?.plan?.executable || state.preflight?.state !== 'PASSED') { toast('A passing host preflight is required.','error'); return; }
  const approved = await confirmAction({title:'Start appliance installation',message:'This mutates the declared management hosts. The run remains resumable and is limited to resources owned by this installation.',phrase:'INSTALL',button:'Start installation'});
  if (!approved) return;
  try { await api('/api/v1/start',{method:'POST',body:{installation:state.plannedRequest}}); toast('Installation accepted.'); navigate('progress'); setTimeout(refreshStatus,500); } catch (error) { toast(error.message,'error'); }
};
$('#resume-installation').onclick = async () => {
  const approved = await confirmAction({title:'Resume installation',message:'The installer will continue from the first failed or pending step using the persisted request and evidence.',button:'Resume'});
  if (!approved) return;
  try { await api('/api/v1/resume',{method:'POST',body:{}}); toast('Resume accepted.'); setTimeout(refreshStatus,500); } catch (error) { toast(error.message,'error'); }
};

function renderBundle(bundle) {
  state.bundle = bundle;
  const target = $('#bundle-status');
  if (!bundle || bundle.verified !== true) {
    const message = bundle?.error || 'Bundle admission has not passed.';
    target.innerHTML = `<div class="error-box">${esc(message)}</div>`;
    if ($('#bundle-health-status')) $('#bundle-health-status').innerHTML = detailsHTML([['State','BLOCKED'],['Reason',message]]);
    return;
  }
  const rows = [
    ['State','VERIFIED'],['Bundle version',bundle.version],['RKE2 version',bundle.rke2Version],
    ['Bundle digest',bundle.bundleDigest],['Lock digest',bundle.lockDigest],['Artifacts',bundle.artifactCount],
    ['Total bytes',Number(bundle.totalBytes || 0).toLocaleString()],['Required images',(bundle.requiredImages || []).length]
  ];
  target.innerHTML = detailsHTML(rows);
  if ($('#bundle-health-status')) $('#bundle-health-status').innerHTML = detailsHTML(rows);
}
async function loadBundleStatus(options = {}) {
  try { const bundle = await api('/api/v1/bundle/status', options); renderBundle(bundle); return bundle; }
  catch (error) { const blocked={verified:false,error:error.message}; renderBundle(blocked); return blocked; }
}
$('#verify-bundle').onclick = async () => { if (!state.connected) { toast('Connect first.','error'); return; } const bundle=await loadBundleStatus(); toast(bundle.verified ? 'Bundle verification passed.' : bundle.error, bundle.verified ? 'success' : 'error'); };

function renderStatus(status, health) {
  state.status = status;
  renderResetStatus(status); state.health = health;
  const run = status.run;
  $('#overview-version').textContent = `Version ${health?.version || run?.version || '—'}`;
  $('#metric-execution').textContent = status.executionEnabled ? 'Enabled' : 'Plan only';
  $('#metric-execution-help').textContent = status.executionEnabled ? 'Host mutation may start after approval' : 'Execution environment variable is disabled';
  $('#global-alert').hidden = status.executionEnabled;
  if (!status.executionEnabled) $('#global-alert').innerHTML = 'Execution is disabled. Planning and evidence inspection remain available; host mutation cannot start.';
  if (!run) {
    $('#overview-state').className='state-pill neutral'; $('#overview-state').textContent='NOT STARTED';
    $('#metric-profile').textContent='—'; $('#metric-profile-help').textContent='No persisted installation request';
    $('#metric-progress').textContent='0 / 0'; $('#metric-progress-help').textContent='No steps executed';
    $('#metric-evidence').textContent='Pending'; $('#metric-evidence-help').textContent='Runtime verification not complete';
    $('#next-action').innerHTML='<strong>Create a validated plan</strong><p>Open Installation, provide real environment values and resolve every blocker.</p><button class="primary" type="button" data-go="installation">Open installation</button>';
    $('#run-summary').innerHTML='<div class="empty-state">No installation run exists.</div>';
    $('#run-progress').innerHTML='<div class="empty-state">No run loaded.</div>';
    $('#resume-installation').disabled=true;
    return;
  }
  $('#overview-state').className=`state-pill ${stateClass(run.state)}`; $('#overview-state').textContent=run.state;
  $('#metric-profile').textContent=run.request?.profileId || '—'; $('#metric-profile-help').textContent=run.simulation ? 'Simulation runtime' : 'Host runtime';
  const succeeded=(run.steps||[]).filter(step=>step.state==='SUCCEEDED'||step.state==='SKIPPED').length;
  $('#metric-progress').textContent=`${succeeded} / ${(run.steps||[]).length}`; $('#metric-progress-help').textContent=run.state==='RUNNING'?'Execution in progress':`Last updated ${formatDate(run.updatedAt)}`;
  const verify=(run.steps||[]).find(step=>step.key==='verify-runtime');
  $('#metric-evidence').textContent=verify?.state==='SUCCEEDED'?'Verified':'Pending'; $('#metric-evidence-help').textContent=verify?.state==='SUCCEEDED'?'Authenticated persistence restart check passed':'Final runtime verification has not passed';
  const interrupted = run.state==='RUNNING' && status.bootstrapActive !== true;
  const action = run.state==='FAILED' ? ['Resume failed run','Review the failed step, correct its prerequisite and resume from persisted state.','progress'] : interrupted ? ['Resume interrupted run','The persisted run is RUNNING but no installer worker owns it. Resume from durable state.','progress'] : run.state==='RUNNING' ? ['Monitor execution','The installer is running. Do not start a second run.','progress'] : run.state==='SUCCEEDED' ? ['Review health and backups','Confirm GitOps, HA, air-gap and create the first off-node backup.','health'] : ['Continue installation','Open progress for the current run.','progress'];
  $('#next-action').innerHTML=`<strong>${esc(action[0])}</strong><p>${esc(action[1])}</p><button class="primary" type="button" data-go="${action[2]}">Open</button>`;
  $('#run-summary').innerHTML=detailsHTML([['Run ID',run.id],['Spec digest',shortDigest(run.specDigest)],['Bundle digest',shortDigest(run.bundleDigest)],['Preflight digest',shortDigest(run.preflightDigest)],['Created',formatDate(run.createdAt)],['Updated',formatDate(run.updatedAt)],['Last error',run.lastError || 'None']]);
  $('#run-progress').innerHTML=(run.steps||[]).map((step,index)=>`<div class="timeline-item ${String(step.state).toLowerCase()}"><span class="timeline-index">${index+1}</span><div><h4>${esc(step.title)}</h4><p>${esc(step.key)} · attempt ${esc(step.attempt || 0)}${step.startedAt?`<br>Started ${esc(formatDate(step.startedAt))}`:''}${step.error?`<br>${esc(step.error)}`:''}</p></div>${pill(step.state)}</div>`).join('');
  $('#resume-installation').disabled=!status.executionEnabled || !(run.state==='FAILED' || interrupted);
}
async function coordinatedRequest(key, work){
  const previous=state.requests.get(key);if(previous)previous.abort();
  const controller=new AbortController();state.requests.set(key,controller);
  try{return await work(controller.signal);}
  catch(error){if(error?.name==='AbortError')return null;throw error;}
  finally{if(state.requests.get(key)===controller)state.requests.delete(key);}
}
function renderResetStatus(status) {
  const runs=Array.isArray(status?.resetRuns)?status.resetRuns:[];
  const latest=runs.length?runs[runs.length-1]:null;
  if(!latest){
    $('#reset-status').innerHTML='<div class="empty-state">No reset run exists.</div>';
  }else{
    const completed=(latest.steps||[]).filter(step=>step.state==='SUCCEEDED').length;
    $('#reset-status').innerHTML=detailsHTML([
      ['Authority',latest.authority||'—'],['Reset ID',latest.id||'—'],['Source run',latest.sourceRunId||'—'],['State',latest.state||'—'],
      ['Progress',`${completed} / ${(latest.steps||[]).length}`],['Updated',formatDate(latest.updatedAt)],['Last error',latest.lastError||'None']
    ]);
  }
  const source=status?.run;
  const blocking=latest&&latest.state!=='SUCCEEDED';
  $('#start-reset').disabled=!status?.executionEnabled || !source || !['SUCCEEDED','FAILED'].includes(source.state) || Boolean(blocking) || status?.resetActive===true || status?.bootstrapActive===true;
  $('#resume-reset').disabled=!status?.executionEnabled || !blocking || status?.resetActive===true;
}

$('#start-reset').onclick=async()=>{
  const source=state.status?.run;if(!source)return;
  const ok=await confirmAction({title:'Reset installation',message:`Reset ${source.id}. Product-owned RKE2 and generated installer/lifecycle state will be removed. Off-node backups, installer access token and pinned SSH trust are preserved.`,phrase:'RESET',button:'Reset installation'});
  if(!ok)return;
  try{await api('/api/v1/reset/start',{method:'POST',headers:{'X-Confirm-Reset':`reset:${source.id}`},body:{}});toast('Journaled reset accepted.');setTimeout(refreshStatus,500);}catch(error){toast(error.message,'error');}
};
$('#resume-reset').onclick=async()=>{
  const runs=state.status?.resetRuns||[];const latest=runs.length?runs[runs.length-1]:null;if(!latest||latest.state==='SUCCEEDED')return;
  const ok=await confirmAction({title:'Resume interrupted reset',message:`Resume reset ${latest.id} from its durable step boundary.`,phrase:'RESUME',button:'Resume reset'});if(!ok)return;
  try{await api('/api/v1/reset/resume',{method:'POST',headers:{'X-Confirm-Reset-Resume':`resume:${latest.id}`},body:{}});toast('Reset resume accepted.');setTimeout(refreshStatus,500);}catch(error){toast(error.message,'error');}
};

async function refreshStatus() {
  if (!state.token || document.visibilityState==='hidden') return;
  return coordinatedRequest('status', async signal => {
    try {
      const [status,health,bundle,preflight,accessSecurity] = await Promise.all([api('/api/v1/status',{signal}),fetch('/healthz',{signal}).then(r=>r.json()),loadBundleStatus({signal}),api('/api/v1/preflight',{signal}),loadAccessSecurity({signal})]);
      if(signal.aborted)return;state.connectionFailures=0;setConnection(true); renderStatus(status,health); renderBundle(bundle);
      if (preflight?.state && preflight.state !== 'NOT_RUN') renderPreflight(preflight);
      if (status?.run) await loadDiagnostics(false);
    } catch (error) { if(error?.name==='AbortError')return;state.connectionFailures++;if(state.connectionFailures>=2)setConnection(false);if (state.token) toast(error.message,'error'); }
  });
}
$('#next-action').onclick = event => { const button=event.target.closest('[data-go]'); if(button) navigate(button.dataset.go); };

async function loadConfiguration() {
  const [profiles,integrations] = await Promise.all([api('/api/v1/profiles'),api('/api/v1/integrations')]);
  state.profiles=profiles; state.integrations=integrations;
  $('#profile').innerHTML=profiles.map(profile=>`<option value="${esc(profile.id)}" ${profile.default?'selected':''}>${esc(profile.displayName)}${profile.default?' · default':''}</option>`).join('');
  renderServices(); syncProfile(); syncInfrastructure(); syncTLS();
}

function renderAccessSecurity(status) {
  state.accessSecurity = status;
  const transport = status?.transport || {};
  const token = status?.token || {};
  const rows = [
    ['Product version', status?.productVersion || '—'],
    ['Installer binary digest', status?.installerBinaryDigest || '—'],
    ['Transport mode', transport.mode || 'UNKNOWN'],
    ['Listen', transport.listen || '—'],
    ['Transport protected', String(transport.transportProtected === true)],
    ['Loopback only', String(transport.loopbackOnly === true)],
    ['Insecure override', String(transport.insecureOverride === true)],
    ['Certificate fingerprint', transport.certificateFingerprint || '—'],
    ['Certificate expires', formatDate(transport.certificateNotAfter)],
    ['Authentication', token.authentication || '—'],
    ['Token source', token.source || '—'],
    ['Token fingerprint', token.fingerprint || '—'],
    ['Token rotated', formatDate(token.rotatedAt)]
  ];
  $('#access-security-status').innerHTML = detailsHTML(rows);
}
async function loadAccessSecurity(options = {}) {
  const status = await api('/api/v1/access/status', options);
  renderAccessSecurity(status);
  return status;
}

function renderHealth(target,data) {
  const rows=flatten(data).filter(([,value])=>typeof value!=='object').slice(0,28);
  $(target).innerHTML=detailsHTML(rows.length?rows:[['State','NOT STARTED']]);
}
function renderFieldEvidence(report, verification = null) {
  state.fieldEvidence = report;
  const rows = [
    ['State',report?.metadata?.state || 'NOT READY'],['Report ID',report?.metadata?.id || '—'],['Evidence digest',report?.metadata?.evidenceDigest || '—'],
    ['Execution mode',report?.evidence?.inputs?.executionMode || '—'],['Run ID',report?.evidence?.inputs?.runId || '—'],
    ['Exact release digest',report?.evidence?.inputs?.releaseArtifactDigest || '—'],['Running installer digest',report?.evidence?.inputs?.installerBinaryDigest || '—'],
    ['Installation succeeded',String(report?.claims?.installationSucceeded === true)],['Live execution observed',String(report?.claims?.liveExecutionObserved === true)],
    ['Runtime certified',String(report?.claims?.runtimeCertified === true)],['Production ready',String(report?.claims?.productionReady === true)]
  ];
  if (verification) rows.push(['Independent verification',verification.valid ? 'VALID' : 'INVALID']);
  $('#field-evidence-status').innerHTML = detailsHTML(rows);
}
async function loadFieldEvidence(showError = false) {
  try { const report = await api('/api/v1/field-evidence/report'); renderFieldEvidence(report); return report; }
  catch (error) { if (showError) toast(error.message,'error'); $('#field-evidence-status').innerHTML=`<div class="empty-state">${esc(error.message)}</div>`; return null; }
}
function downloadJSONFile(name,value) {
  const blob=new Blob([JSON.stringify(value,null,2)+'\n'],{type:'application/json'}),url=URL.createObjectURL(blob),anchor=document.createElement('a');
  anchor.href=url;anchor.download=name;anchor.click();URL.revokeObjectURL(url);
}
$('#download-field-evidence').onclick=async()=>{const report=await loadFieldEvidence(true);if(report)downloadJSONFile(`field-execution-evidence-${report.metadata.id}.json`,report);};
$('#verify-field-evidence').onclick=async()=>{const report=state.fieldEvidence||await loadFieldEvidence(true);if(!report)return;try{const result=await api('/api/v1/field-evidence/verify',{method:'POST',body:report});renderFieldEvidence(report,result);toast('Field evidence verification passed.');}catch(error){toast(error.message,'error');}};

function renderDiagnostics(report, verification = null) {
  state.fieldDiagnostics = report;
  const failed = report?.analysis?.failedStep;
  const rows = [
    ['Status',report?.analysis?.status || 'NOT READY'],['Report ID',report?.metadata?.id || '—'],['Digest',report?.metadata?.digest || '—'],
    ['Run ID',report?.snapshots?.installationRun?.id || '—'],['Run state',report?.snapshots?.installationRun?.state || '—'],
    ['Category',report?.analysis?.category || '—'],['Owning layer',report?.analysis?.owningLayer || '—'],
    ['Retry disposition',report?.analysis?.retryDisposition || '—'],['Failed step',failed ? `${failed.key} · ${failed.title}` : 'None'],
    ['Attempt',failed?.attempt ?? '—'],['Summary',report?.analysis?.summary || '—'],['Next action',report?.analysis?.nextAction || '—'],
    ['Automatic retry',String(report?.claims?.automaticRetry === true)],['Runtime certified',String(report?.claims?.runtimeCertified === true)]
  ];
  if (verification) rows.push(['Independent verification',verification.valid ? 'VALID' : 'INVALID']);
  $('#diagnostics-status').innerHTML = detailsHTML(rows);
}
async function loadDiagnostics(showError = false) {
  try { const report = await api('/api/v1/diagnostics/report'); renderDiagnostics(report); return report; }
  catch (error) { if (showError) toast(error.message,'error'); $('#diagnostics-status').innerHTML=`<div class="empty-state">${esc(error.message)}</div>`; return null; }
}
$('#download-diagnostics').onclick=async()=>{const report=await loadDiagnostics(true);if(report)downloadJSONFile(`field-diagnostic-${report.metadata.id}.json`,report);};
$('#verify-diagnostics').onclick=async()=>{const report=state.fieldDiagnostics||await loadDiagnostics(true);if(!report)return;try{const result=await api('/api/v1/diagnostics/verify',{method:'POST',body:report});renderDiagnostics(report,result);toast('Diagnostic verification passed.');}catch(error){toast(error.message,'error');}};

async function refreshHealth() {
  if (!state.connected) return;
  try {
    const [accessSecurity,bundle,gitops,ha,airgap]=await Promise.all([loadAccessSecurity(),loadBundleStatus(),api('/api/v1/gitops/status'),api('/api/v1/ha/status'),api('/api/v1/airgap/status')]);
    renderAccessSecurity(accessSecurity); renderBundle(bundle); renderHealth('#gitops-status',gitops); renderHealth('#ha-status',ha); renderHealth('#airgap-status',airgap); await loadFieldEvidence(false); await loadDiagnostics(false);
  } catch(error){ toast(error.message,'error'); }
}
$('#refresh-health').onclick=refreshHealth;

async function downloadCA() {
  if(!state.token){toast('Connect first.','error');return;}
  const response=await fetch('/api/v1/tls/ca',{headers:{Authorization:`Bearer ${state.token}`}});
  if(!response.ok){const payload=await response.json().catch(()=>null);toast(errorMessage(payload,'Bootstrap CA is not ready.'),'error');return;}
  const blob=await response.blob(),url=URL.createObjectURL(blob),anchor=document.createElement('a');
  anchor.href=url; anchor.download='4so-platform-bootstrap-ca.crt'; anchor.click(); URL.revokeObjectURL(url);
}
$('#download-ca').onclick=downloadCA;

function runItem(run, actions='') {
  const authority=[run.service||run.objectPrefix||'',run.backupId?`backup ${run.backupId}`:'',run.profileId||''].filter(Boolean).map(esc).join(' · ');
  return `<div class="resource-item"><div><h3>${esc(run.action || run.service || 'Run')} · ${esc(run.id || run.backupId || '')}</h3><p>${authority}${run.createdAt?` · ${esc(formatDate(run.createdAt))}`:''}${run.error?`<br>${esc(run.error)}`:''}</p></div><div class="resource-actions">${pill(run.state || 'AVAILABLE')}${run.recoveryRequired?pill('RECOVERY REQUIRED'):''}${actions}</div></div>`;
}
async function refreshDR() {
  if(!state.connected)return;
  try{
    const runs=await api('/api/v1/disaster-recovery/runs'); state.drRuns=[...runs].sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
    const backups=state.drRuns.filter(run=>run.action==='backup'&&run.state==='SUCCEEDED'&&run.backupId);
    $('#dr-backups').innerHTML=backups.length?backups.map(run=>runItem(run,`<button class="danger small" type="button" data-dr-restore="${esc(run.backupId)}">Restore</button>`)).join(''):'<div class="empty-state">No completed appliance backup exists.</div>';
    $('#dr-runs').innerHTML=state.drRuns.length?state.drRuns.slice(0,30).map(run=>runItem(run)).join(''):'<div class="empty-state">No disaster-recovery run exists.</div>';
  }catch(error){$('#dr-runs').innerHTML=`<div class="error-box">${esc(error.message)}</div>`;}
}
$('#create-dr-backup').onclick=async()=>{const ok=await confirmAction({title:'Create appliance backup',message:'A new off-node backup will be written to the S3-compatible target configured in the persisted installation request.',button:'Create backup'});if(!ok)return;try{await api('/api/v1/disaster-recovery/backup',{method:'POST',body:{}});toast('Backup accepted.');setTimeout(refreshDR,500);}catch(error){toast(error.message,'error');}};
$('#dr-backups').onclick=async event=>{const button=event.target.closest('[data-dr-restore]');if(!button)return;const id=button.dataset.drRestore;const ok=await confirmAction({title:'Restore appliance backup',message:`Restore point ${id} will replace managed authority and embedded service data according to the recovery contract.`,phrase:'RESTORE',button:'Start restore'});if(!ok)return;try{await api('/api/v1/disaster-recovery/restore',{method:'POST',headers:{'X-Confirm-Restore':`restore:${id}`},body:{backupId:id}});toast('Restore accepted.');setTimeout(refreshDR,500);}catch(error){toast(error.message,'error');}};

async function refreshLifecycle() {
  if(!state.connected)return;
  const service=$('#lifecycle-service').value;
  try{
    const [backups,runs]=await Promise.all([api(`/api/v1/lifecycle/backups/${encodeURIComponent(service)}`),api('/api/v1/lifecycle/runs')]);
    state.lifecycleBackups=backups; state.lifecycleRuns=[...runs].sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
    $('#service-backups').innerHTML=backups.length?backups.map(backup=>`<div class="resource-item"><div><h3>${esc(backup.id)}</h3><p>${esc(formatDate(backup.createdAt))} · ${(backup.files||[]).length} files · ${(backup.files||[]).reduce((sum,file)=>sum+(file.size||0),0).toLocaleString()} bytes</p></div><div class="resource-actions"><button class="danger small" type="button" data-service-restore="${esc(backup.id)}">Restore</button></div></div>`).join(''):'<div class="empty-state">No backup exists for this service.</div>';
    $('#lifecycle-runs').innerHTML=state.lifecycleRuns.length?state.lifecycleRuns.slice(0,40).map(run=>{const recovery=run.action==='upgrade'&&run.state==='FAILED'&&run.upgradePhase==='RECOVERY_REQUIRED'?`<button class="danger small" type="button" data-upgrade-recovery="${esc(run.id)}">Recover from bound backup</button>`:'';return runItem(run,recovery);}).join(''):'<div class="empty-state">No lifecycle run exists.</div>';
  }catch(error){$('#lifecycle-runs').innerHTML=`<div class="error-box">${esc(error.message)}</div>`;}
}
$('#lifecycle-service').onchange=refreshLifecycle;
$('#backup-service').onclick=async()=>{const service=$('#lifecycle-service').value;try{await api('/api/v1/lifecycle/backup',{method:'POST',body:{service}});toast('Service backup accepted.');setTimeout(refreshLifecycle,500);}catch(error){toast(error.message,'error');}};
$('#service-backups').onclick=async event=>{const button=event.target.closest('[data-service-restore]');if(!button)return;const service=$('#lifecycle-service').value,backupId=button.dataset.serviceRestore;const ok=await confirmAction({title:`Restore ${service}`,message:`Restore verified backup ${backupId}. Only product-managed service data is affected.`,phrase:'RESTORE',button:'Start restore'});if(!ok)return;try{await api('/api/v1/lifecycle/restore',{method:'POST',headers:{'X-Confirm-Restore':`restore:${service}:${backupId}`},body:{service,backupId}});toast('Service restore accepted.');setTimeout(refreshLifecycle,500);}catch(error){toast(error.message,'error');}};
$('#upgrade-service').onclick=async()=>{const service=$('#lifecycle-service').value,image=$('#upgrade-image').value.trim();if(!/@sha256:[a-f0-9]{64}$/i.test(image)){toast('Enter an immutable image reference ending in @sha256:<64 hex>.','error');return;}const ok=await confirmAction({title:`Upgrade ${service}`,message:`The service will be backed up before upgrade to ${image}.`,phrase:'UPGRADE',button:'Backup and upgrade'});if(!ok)return;try{await api('/api/v1/lifecycle/upgrade',{method:'POST',body:{service,image}});toast('Upgrade accepted.');setTimeout(refreshLifecycle,500);}catch(error){toast(error.message,'error');}};
$('#lifecycle-runs').onclick=async event=>{const button=event.target.closest('[data-upgrade-recovery]');if(!button)return;const upgradeRunId=button.dataset.upgradeRecovery;const run=state.lifecycleRuns.find(item=>item.id===upgradeRunId);if(!run)return;const ok=await confirmAction({title:`Recover ${run.service||'service'}`,message:`This destructive recovery will quiesce the service, restore backup ${run.backupId||''}, re-apply previous image ${run.previousImage||''}, then resume and verify it. Writes after the pre-upgrade backup can be lost.`,phrase:'RECOVER',button:'Restore backup and previous version'});if(!ok)return;try{await api('/api/v1/lifecycle/upgrade-recovery',{method:'POST',headers:{'X-Confirm-Upgrade-Recovery':`recover:${upgradeRunId}`},body:{upgradeRunId}});toast('Upgrade recovery accepted.');setTimeout(refreshLifecycle,500);}catch(error){toast(error.message,'error');}};

async function refreshSSHTrust() {
  if(!state.connected)return;
  try{
    const trust=await api('/api/v1/ssh/trust/status'); state.sshTrust=trust;
    const entries=trust.entries||[];
    const summary=[]; const isFa=state.locale==='fa';
    summary.push(trust.privateKeyStored?(isFa?'کلید خصوصی SSH: ذخیره شده':'SSH private key: stored'):(isFa?'کلید خصوصی SSH: ثبت نشده':'SSH private key: missing'));
    summary.push(trust.knownHostsStored?(isFa?`کلیدهای میزبان پین‌شده: ${entries.length}`:`Pinned host keys: ${entries.length}`):(isFa?'کلید میزبان پین‌شده: ثبت نشده':'Pinned host keys: missing'));
    const fingerprints=entries.map(entry=>`${entry.host} · ${entry.keyType} · ${entry.fingerprint}`).join('<br>');
    const rotation=trust.lastRotation;
    const rotationLine=rotation?`<br><small>${esc(isFa?'آخرین چرخش کلید':'Last host-key rotation')}: <span class="technical" dir="ltr">${esc(rotation.host)} · ${esc(rotation.id)}</span></small>`:'';
    $('#ssh-trust-status').innerHTML=`<strong>${esc(summary.join(' · '))}</strong>${fingerprints?`<br><span class="technical" dir="ltr">${fingerprints.split('<br>').map(esc).join('<br>')}</span>`:''}${rotationLine}`;
  }catch(error){$('#ssh-trust-status').innerHTML=`<span class="error-text">${esc(error.message)}</span>`;}
}

$('#connect-button').onclick=()=>{$('#bootstrap-token').value=state.token;$('#connect-error').hidden=true;$('#connect-dialog').showModal();};
$('#confirm-connect').onclick=async()=>{
  const token=$('#bootstrap-token').value.trim(); if(!token){$('#connect-error').textContent='Bootstrap token is required.';$('#connect-error').hidden=false;return;}
  state.token=token;
  try{
    const status=await api('/api/v1/status');
    sessionStorage.setItem('platformInstallerToken',token); setConnection(true); $('#connect-dialog').close();
    const [health,bundle,accessSecurity]=await Promise.all([fetch('/healthz').then(r=>r.json()),loadBundleStatus(),loadAccessSecurity()]); renderStatus(status,health); renderBundle(bundle); renderAccessSecurity(accessSecurity); await Promise.all([loadConfiguration(),refreshSSHTrust()]);
    toast('Connected to installer.');
    if(state.page==='health')refreshHealth(); if(state.page==='recovery')refreshDR(); if(state.page==='lifecycle')refreshLifecycle();
  }catch(error){state.token='';$('#connect-error').textContent=error.message;$('#connect-error').hidden=false;}
};
$('#open-ssh-key').onclick=()=>{$('#ssh-private-key').value='';$('#ssh-dialog').showModal();};
$('#store-ssh-key').onclick=async()=>{const key=$('#ssh-private-key').value.trim();if(!key){toast('Paste a valid OpenSSH private key.','error');return;}try{await api('/api/v1/secrets/ssh-private-key',{method:'POST',body:{privateKey:key}});$('#ssh-private-key').value='';$('#ssh-dialog').close();$('#credential-ref').value='secret://installer/ssh-private-key';toast('SSH private key stored securely.');await refreshSSHTrust();}catch(error){toast(error.message,'error');}};
$('#open-ssh-known-hosts').onclick=()=>{$('#ssh-known-hosts').value='';$('#ssh-known-hosts-dialog').showModal();};
$('#store-ssh-known-hosts').onclick=async()=>{const knownHosts=$('#ssh-known-hosts').value.trim();if(!knownHosts){toast('Paste trusted known_hosts entries for the HA peers.','error');return;}try{const result=await api('/api/v1/secrets/ssh-known-hosts',{method:'POST',body:{knownHosts}});$('#ssh-known-hosts').value='';$('#ssh-known-hosts-dialog').close();state.sshTrust=result;await refreshSSHTrust();toast('Pinned HA host keys stored.');}catch(error){toast(error.message,'error');}};
$('#open-ssh-host-rotation').onclick=()=>{const trust=state.sshTrust||{};const entries=trust.entries||[];$('#ssh-rotation-host').value='';$('#ssh-rotation-fingerprints').value='';$('#ssh-rotation-known-hosts').value='';if(entries.length===1){$('#ssh-rotation-host').value=entries[0].host;$('#ssh-rotation-fingerprints').value=entries[0].fingerprint;}$('#ssh-host-rotation-dialog').showModal();};
$('#rotate-ssh-host-key').onclick=async()=>{const host=$('#ssh-rotation-host').value.trim();const expectedCurrentFingerprints=$('#ssh-rotation-fingerprints').value.split(/\r?\n/).map(value=>value.trim()).filter(Boolean);const replacementKnownHosts=$('#ssh-rotation-known-hosts').value.trim();if(!host||!expectedCurrentFingerprints.length||!replacementKnownHosts){toast('Host, current fingerprints and complete replacement known_hosts are required.','error');return;}try{const result=await api('/api/v1/ssh/trust/rotate',{method:'POST',body:{host,expectedCurrentFingerprints,replacementKnownHosts}});state.sshTrust=result.trust;$('#ssh-host-rotation-dialog').close();await refreshSSHTrust();toast('Pinned HA host key rotated with durable evidence.');}catch(error){toast(error.message,'error');}};

document.addEventListener('click',event=>{const go=event.target.closest('[data-go]');if(go)navigate(go.dataset.go);});
applyLocale(); setConnection(false); renderServices(); syncTLS(); syncInfrastructure();
if(state.token){refreshStatus().then(loadConfiguration).catch(()=>{});} else setTimeout(()=>$('#connect-dialog').showModal(),150);
function scheduleInstallerPoll(delay=5000){
  clearTimeout(scheduleInstallerPoll.timer);
  scheduleInstallerPoll.timer=setTimeout(async()=>{
    if(document.visibilityState==='visible'&&state.connected){
      await refreshStatus();
      if(state.page==='health')await refreshHealth();
      if(state.page==='recovery')await refreshDR();
      if(state.page==='lifecycle')await refreshLifecycle();
    }
    scheduleInstallerPoll(state.connected?5000:10000);
  },delay);
}
document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')scheduleInstallerPoll(250);});
scheduleInstallerPoll(3000);
