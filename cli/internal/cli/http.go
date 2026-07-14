package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/o-clan/asiri/cli/internal/store"
)

func postJSON(url string, body any, out any) error {
	status, err := postJSONStatus(url, body, out)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", status)
	}
	return nil
}

func postJSONBearer(st *store.FileStore, url, bearer string, body any, out any) error {
	status, err := postJSONBearerStatus(st, url, bearer, body, out)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", status)
	}
	return nil
}

func postJSONBearerStatus(st *store.FileStore, url, bearer string, body any, out any) (int, error) {
	return postJSONBearerStatusWithClient(st, http.DefaultClient, url, bearer, body, out)
}

func postJSONBearerTimeout(st *store.FileStore, url, bearer string, body any, out any, timeout time.Duration) error {
	status, err := postJSONBearerStatusWithClient(st, &http.Client{Timeout: timeout}, url, bearer, body, out)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", status)
	}
	return nil
}

func postJSONBearerStatusWithClient(st *store.FileStore, client *http.Client, url, bearer string, body any, out any) (int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	bearer = latestControlPlaneBearer(st, bearer)
	status, responseBody, err := sendPostJSONBearer(st, client, url, bearer, encoded)
	if err != nil {
		return status, err
	}
	if status == http.StatusUnauthorized {
		if refreshed, ok, err := refreshBearerAfterUnauthorized(st, bearer); err != nil {
			return status, err
		} else if ok {
			status, responseBody, err = sendPostJSONBearer(st, client, url, refreshed, encoded)
			if err != nil {
				return status, err
			}
		}
	}
	return decodeBearerResponse(status, responseBody, out, st)
}

func sendPostJSONBearer(st *store.FileStore, client *http.Client, url, bearer string, encoded []byte) (int, []byte, error) {
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")
	request.Header.Set("authorization", "Bearer "+bearer)
	if err := signBearerRequest(st, request, encoded, bearer); err != nil {
		return 0, nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, nil, err
	}
	return response.StatusCode, responseBody, nil
}

func getJSONBearer(st *store.FileStore, url, bearer string, out any) error {
	status, err := getJSONBearerStatus(st, url, bearer, out)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", status)
	}
	return nil
}

func getJSONBearerStatus(st *store.FileStore, url, bearer string, out any) (int, error) {
	bearer = latestControlPlaneBearer(st, bearer)
	status, responseBody, err := sendGetJSONBearer(st, http.DefaultClient, url, bearer)
	if err != nil {
		return status, err
	}
	if status == http.StatusUnauthorized {
		if refreshed, ok, err := refreshBearerAfterUnauthorized(st, bearer); err != nil {
			return status, err
		} else if ok {
			status, responseBody, err = sendGetJSONBearer(st, http.DefaultClient, url, refreshed)
			if err != nil {
				return status, err
			}
		}
	}
	return decodeBearerResponse(status, responseBody, out, st)
}

func sendGetJSONBearer(st *store.FileStore, client *http.Client, url, bearer string) (int, []byte, error) {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("authorization", "Bearer "+bearer)
	if err := signBearerRequest(st, request, nil, bearer); err != nil {
		return 0, nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, nil, err
	}
	return response.StatusCode, responseBody, nil
}

func decodeBearerResponse(status int, responseBody []byte, out any, st *store.FileStore) (int, error) {
	if status < 200 || status >= 300 {
		failure := parseControlPlaneFailure(responseBody)
		if status == http.StatusNotFound {
			return status, nil
		}
		if failure.Message != "" {
			return status, fmt.Errorf("control plane returned HTTP %d: %s", status, failure.Message)
		}
		if failure.Error != "" {
			return status, fmt.Errorf("control plane returned HTTP %d: %s", status, failure.Error)
		}
		return status, nil
	}
	if out != nil && len(bytes.TrimSpace(responseBody)) > 0 {
		if err := json.Unmarshal(responseBody, out); err != nil {
			return status, fmt.Errorf("control plane returned invalid JSON response: %w", err)
		}
	}
	return status, nil
}

func refreshBearerAfterUnauthorized(st *store.FileStore, bearer string) (string, bool, error) {
	if st == nil || st.State.ControlPlane == nil || st.State.ControlPlane.Origin == "" {
		return "", false, nil
	}
	current, err := st.ControlPlaneAccessToken()
	if err != nil || current != bearer {
		return "", false, nil
	}
	refreshed, err := refreshControlPlaneAccess(st.State.ControlPlane.Origin, st)
	if err != nil {
		return "", false, err
	}
	return refreshed, true, nil
}

func latestControlPlaneBearer(st *store.FileStore, fallback string) string {
	if st == nil || st.State.ControlPlane == nil {
		return fallback
	}
	current, err := st.ControlPlaneAccessToken()
	if err != nil || current == "" {
		return fallback
	}
	return current
}

func signBearerRequest(st *store.FileStore, request *http.Request, body []byte, bearer string) error {
	return signDeviceRequest(st, request, body, credentialHash(bearer))
}

func signDeviceRequest(st *store.FileStore, request *http.Request, body []byte, credentialHash string) error {
	if st.State.ControlPlane == nil || st.State.ControlPlane.DeviceID == "" {
		return errors.New("control plane device is not linked")
	}
	return signDeviceRequestForDevice(st, request, body, credentialHash, st.State.ControlPlane.DeviceID)
}

func signDeviceRequestForDevice(st *store.FileStore, request *http.Request, body []byte, credentialHash, remoteDeviceID string) error {
	if remoteDeviceID == "" {
		return errors.New("remote control plane device is required")
	}
	if credentialHash == "" {
		return errors.New("device request credential binding is required")
	}
	privateKey, err := st.DeviceSigningPrivateKey()
	if err != nil {
		return err
	}
	bodyDigest := sha256.Sum256(body)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	canonical := strings.Join([]string{
		"asiri-device-request-v1",
		request.Method,
		request.URL.RequestURI(),
		hex.EncodeToString(bodyDigest[:]),
		timestamp,
		nonce,
		remoteDeviceID,
		credentialHash,
	}, "\n")
	canonicalDigest := sha256.Sum256([]byte(canonical))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, canonicalDigest[:])
	if err != nil {
		return err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	request.Header.Set("x-asiri-device", remoteDeviceID)
	request.Header.Set("x-asiri-timestamp", timestamp)
	request.Header.Set("x-asiri-nonce", nonce)
	request.Header.Set("x-asiri-signature", base64.RawURLEncoding.EncodeToString(signature))
	return nil
}

func signDeviceCodeClaimRequest(st *store.FileStore, request *http.Request, body []byte, credentialHash string) error {
	if credentialHash == "" {
		return errors.New("device-code claim credential binding is required")
	}
	privateKey, err := st.LocalDeviceSigningPrivateKey()
	if err != nil {
		return err
	}
	bodyDigest := sha256.Sum256(body)
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	canonical := strings.Join([]string{
		"asiri-device-code-claim-v1",
		request.Method,
		request.URL.RequestURI(),
		hex.EncodeToString(bodyDigest[:]),
		timestamp,
		nonce,
		credentialHash,
	}, "\n")
	canonicalDigest := sha256.Sum256([]byte(canonical))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, canonicalDigest[:])
	if err != nil {
		return err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	request.Header.Set("x-asiri-timestamp", timestamp)
	request.Header.Set("x-asiri-nonce", nonce)
	request.Header.Set("x-asiri-signature", base64.RawURLEncoding.EncodeToString(signature))
	return nil
}

func credentialHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func postJSONDeviceCodeClaimStatus(st *store.FileStore, url string, body any, credentialHash string, out any) (int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return 0, err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")
	if err := signDeviceCodeClaimRequest(st, request, encoded, credentialHash); err != nil {
		return 0, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if err := decodeJSONResponse(response, out); err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, nil
}

func postJSONDeviceSignedStatus(st *store.FileStore, url string, body any, credentialHash string, out any) (int, error) {
	if st.State.ControlPlane == nil || st.State.ControlPlane.DeviceID == "" {
		return 0, errors.New("control plane device is not linked")
	}
	return postJSONDeviceSignedForDeviceStatus(st, url, body, credentialHash, st.State.ControlPlane.DeviceID, out)
}

func postJSONDeviceSignedForDeviceStatus(st *store.FileStore, url string, body any, credentialHash, remoteDeviceID string, out any) (int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return 0, err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")
	if err := signDeviceRequestForDevice(st, request, encoded, credentialHash, remoteDeviceID); err != nil {
		return 0, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if err := decodeJSONResponse(response, out); err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, nil
}

func postJSONStatus(url string, body any, out any) (int, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return 0, err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if err := decodeJSONResponse(response, out); err != nil {
		return response.StatusCode, err
	}
	return response.StatusCode, nil
}

func decodeJSONResponse(response *http.Response, out any) error {
	if out == nil {
		return nil
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(responseBody)) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, out); err != nil {
		return nonJSONControlPlaneResponseError(response, responseBody, err)
	}
	return nil
}

func nonJSONControlPlaneResponseError(response *http.Response, body []byte, decodeErr error) error {
	contentType := response.Header.Get("content-type")
	if response.Header.Get("cf-mitigated") != "" || bytes.Contains(body, []byte("Just a moment")) {
		return fmt.Errorf("control plane returned HTTP %d with a Cloudflare challenge instead of JSON; API routes should bypass WAF challenges and rely on rate limits", response.StatusCode)
	}
	if contentType != "" && !strings.Contains(strings.ToLower(contentType), "json") {
		return fmt.Errorf("control plane returned HTTP %d with non-JSON content type %q", response.StatusCode, contentType)
	}
	return decodeErr
}
