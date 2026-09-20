package main

import (
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	identityv1alpha1 "platform.4so.io/factory/providers/crossplane/apis/identity/v1alpha1"
	providerv1alpha1 "platform.4so.io/factory/providers/crossplane/apis/v1alpha1"
	"platform.4so.io/factory/providers/crossplane/internal/controller/samlbroker"
)

func main() {
	var metricsAddress string
	var probeAddress string
	var leaderElection bool
	flag.StringVar(&metricsAddress, "metrics-bind-address", ":8080", "Metrics listen address.")
	flag.StringVar(&probeAddress, "health-probe-bind-address", ":8081", "Health probe listen address.")
	flag.BoolVar(&leaderElection, "leader-elect", true, "Enable leader election.")
	flag.Parse()

	scheme := runtime.NewScheme()
	must(clientgoscheme.AddToScheme(scheme))
	must(providerv1alpha1.SchemeBuilder.AddToScheme(scheme))
	must(identityv1alpha1.SchemeBuilder.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddress},
		HealthProbeBindAddress: probeAddress,
		LeaderElection:         leaderElection,
		LeaderElectionID:       "provider-crossplane.platform.4so.io",
	})
	must(err)
	must(samlbroker.Setup(mgr))
	must(mgr.AddHealthzCheck("healthz", healthz.Ping))
	must(mgr.AddReadyzCheck("readyz", healthz.Ping))
	must(mgr.Start(ctrl.SetupSignalHandler()))
}

func must(err error) {
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}
