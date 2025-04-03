package gce

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// InstanceMetadata contains GCE instance metadata
type InstanceMetadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Zone        string `json:"zone"`
	MachineType string `json:"machineType"`
	ProjectID   string `json:"projectId"`
	ShieldedVM  bool   `json:"isShieldedVM"`
	VTPM        bool   `json:"hasVTPM"`
}

// IsRunningOnGCE checks if the code is running on a GCE VM
func IsRunningOnGCE() bool {
	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	req, err := http.NewRequest("GET", "http://metadata.google.internal", nil)
	if err != nil {
		return false
	}

	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// GetInstanceMetadata retrieves the GCE instance metadata
func GetInstanceMetadata() (*InstanceMetadata, error) {
	if !IsRunningOnGCE() {
		return nil, fmt.Errorf("not running on GCE")
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Helper function to get metadata
	getMetadata := func(path string) (string, error) {
		req, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/"+path, nil)
		if err != nil {
			return "", err
		}
		req.Header.Add("Metadata-Flavor", "Google")

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("metadata server returned status %d", resp.StatusCode)
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		return string(data), nil
	}

	// Collect instance metadata
	meta := &InstanceMetadata{}

	meta.ID, _ = getMetadata("instance/id")
	meta.Name, _ = getMetadata("instance/name")
	meta.Zone, _ = getMetadata("instance/zone")
	meta.MachineType, _ = getMetadata("instance/machine-type")
	meta.ProjectID, _ = getMetadata("project/project-id")

	// Check if it's a Shielded VM with vTPM
	shieldedConfig, err := getMetadata("instance/shielded-instance-config/")
	if err == nil {
		var config map[string]bool
		if err := json.Unmarshal([]byte(shieldedConfig), &config); err == nil {
			meta.ShieldedVM = true
			meta.VTPM = config["enableVtpm"]
		}
	}

	return meta, nil
}

// HasVTPM checks if the VM has vTPM enabled
func HasVTPM() bool {
	meta, err := GetInstanceMetadata()
	if err != nil {
		return false
	}
	return meta.VTPM
}
