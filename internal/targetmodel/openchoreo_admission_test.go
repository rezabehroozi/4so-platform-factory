package targetmodel
import "testing"
func TestOpenChoreoTargetAdapterAdmissionFailsClosedUntilExactSourceAndLifecycleExist(t *testing.T){
	out:=EvaluateOpenChoreoTargetAdapterAdmission(OpenChoreoTargetAdapterAdmissionInput{DistributionIdentity:"okd",TargetAdmitted:true,CapabilityDiscoveryComplete:true,DuplicateStackResolved:true,ObservedCapabilities:[]string{"networking.ovn-kubernetes","monitoring.cluster","operator-lifecycle.olm","tenancy.projects"}})
	if out.Eligible||out.PhysicalCertificationInferred{t.Fatalf("over-admitted optional adapter: %#v",out)}
	for _,want:=range []string{"OPENCHOREO_EXACT_SOURCE_AUTHORITY_PENDING","OPENCHOREO_DURABLE_LIFECYCLE_CONTRACT_PENDING"}{if !containsString(out.Blockers,want){t.Fatalf("missing blocker %s: %#v",want,out)}}
	for _,want:=range []string{"networking-and-ingress-native","observability-native","operator-lifecycle-native","tenancy-native"}{if !containsString(out.NativeCapabilitySuppressions,want){t.Fatalf("missing suppression %s: %#v",want,out)}}
}
func TestOpenChoreoTargetAdapterAdmissionCanOnlyAdmitSupportedTargetWithAllPrerequisites(t *testing.T){
	out:=EvaluateOpenChoreoTargetAdapterAdmission(OpenChoreoTargetAdapterAdmissionInput{DistributionIdentity:"rke2",TargetAdmitted:true,CapabilityDiscoveryComplete:true,ExactSourceAdmitted:true,Disconnected:true,DisconnectedMirrorAdmitted:true,DurableLifecycleReady:true,DuplicateStackResolved:true})
	if !out.Eligible||len(out.Blockers)!=0||out.PhysicalCertificationInferred{t.Fatalf("expected source admission: %#v",out)}
}

func TestOpenChoreoAdmissionSeparatesLifecycleContractFromExactSourceAcquisition(t *testing.T){
	out:=EvaluateOpenChoreoTargetAdapterAdmission(OpenChoreoTargetAdapterAdmissionInput{
		DistributionIdentity:"okd",
		TargetAdmitted:true,
		CapabilityDiscoveryComplete:true,
		DurableLifecycleReady:true,
		DuplicateStackResolved:true,
		ObservedCapabilities:[]string{"networking.ovn-kubernetes","monitoring.cluster","operator-lifecycle.olm","tenancy.projects"},
	})
	if out.Eligible{t.Fatalf("adapter admitted without exact source: %#v",out)}
	if !containsString(out.Blockers,"OPENCHOREO_EXACT_SOURCE_AUTHORITY_PENDING"){t.Fatalf("exact-source blocker missing: %#v",out.Blockers)}
	if containsString(out.Blockers,"OPENCHOREO_DURABLE_LIFECYCLE_CONTRACT_PENDING"){t.Fatalf("implemented lifecycle contract was incorrectly tied to source acquisition: %#v",out.Blockers)}
}
