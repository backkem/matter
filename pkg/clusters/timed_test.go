package clusters

import (
	"errors"
	"testing"

	"github.com/backkem/matter/pkg/datamodel"
	"github.com/backkem/matter/pkg/im/message"
)

func TestRequireTimed_Timed(t *testing.T) {
	req := datamodel.InvokeRequest{
		InvokeFlags: datamodel.InvokeFlagTimed,
	}

	err := RequireTimed(req)
	if err != nil {
		t.Errorf("RequireTimed() = %v, want nil", err)
	}
}

func TestRequireTimed_NotTimed(t *testing.T) {
	req := datamodel.InvokeRequest{
		InvokeFlags: 0, // Not timed
	}

	err := RequireTimed(req)
	if !errors.Is(err, ErrTimedRequired) {
		t.Errorf("RequireTimed() = %v, want ErrTimedRequired", err)
	}
}

func TestRequireTimedWrite_Timed(t *testing.T) {
	req := datamodel.WriteAttributeRequest{
		WriteFlags: datamodel.WriteFlagTimed,
	}

	err := RequireTimedWrite(req)
	if err != nil {
		t.Errorf("RequireTimedWrite() = %v, want nil", err)
	}
}

func TestRequireTimedWrite_NotTimed(t *testing.T) {
	req := datamodel.WriteAttributeRequest{
		WriteFlags: 0, // Not timed
	}

	err := RequireTimedWrite(req)
	if !errors.Is(err, ErrTimedRequired) {
		t.Errorf("RequireTimedWrite() = %v, want ErrTimedRequired", err)
	}
}

func TestTimedStatus(t *testing.T) {
	status := TimedStatus()
	if status.Status != message.StatusNeedsTimedInteraction {
		t.Errorf("Status = %v, want NeedsTimedInteraction", status.Status)
	}
}

func TestStatusSuccess(t *testing.T) {
	status := StatusSuccess()
	if status.Status != message.StatusSuccess {
		t.Errorf("Status = %v, want Success", status.Status)
	}
}

func TestStatusFailure(t *testing.T) {
	status := StatusFailure()
	if status.Status != message.StatusFailure {
		t.Errorf("Status = %v, want Failure", status.Status)
	}
}

func TestStatusUnsupportedCommand(t *testing.T) {
	status := StatusUnsupportedCommand()
	if status.Status != message.StatusUnsupportedCommand {
		t.Errorf("Status = %v, want UnsupportedCommand", status.Status)
	}
}

func TestStatusUnsupportedAttribute(t *testing.T) {
	status := StatusUnsupportedAttribute()
	if status.Status != message.StatusUnsupportedAttribute {
		t.Errorf("Status = %v, want UnsupportedAttribute", status.Status)
	}
}

func TestStatusUnsupportedWrite(t *testing.T) {
	status := StatusUnsupportedWrite()
	if status.Status != message.StatusUnsupportedWrite {
		t.Errorf("Status = %v, want UnsupportedWrite", status.Status)
	}
}

func TestStatusConstraintError(t *testing.T) {
	status := StatusConstraintError()
	if status.Status != message.StatusConstraintError {
		t.Errorf("Status = %v, want ConstraintError", status.Status)
	}
}

func TestStatusInvalidAction(t *testing.T) {
	status := StatusInvalidAction()
	if status.Status != message.StatusInvalidAction {
		t.Errorf("Status = %v, want InvalidAction", status.Status)
	}
}

func TestStatusResourceExhausted(t *testing.T) {
	status := StatusResourceExhausted()
	if status.Status != message.StatusResourceExhausted {
		t.Errorf("Status = %v, want ResourceExhausted", status.Status)
	}
}

func TestStatusNotFound(t *testing.T) {
	status := StatusNotFound()
	if status.Status != message.StatusNotFound {
		t.Errorf("Status = %v, want NotFound", status.Status)
	}
}

func TestStatusBusy(t *testing.T) {
	status := StatusBusy()
	if status.Status != message.StatusBusy {
		t.Errorf("Status = %v, want Busy", status.Status)
	}
}

func TestClusterStatus(t *testing.T) {
	code := uint8(0x03)
	status := ClusterStatus(code)

	if status.Status != message.StatusSuccess {
		t.Errorf("Status = %v, want Success", status.Status)
	}
	if status.ClusterStatus == nil {
		t.Fatal("ClusterStatus = nil, want non-nil")
	}
	if *status.ClusterStatus != code {
		t.Errorf("ClusterStatus = %d, want %d", *status.ClusterStatus, code)
	}
}
