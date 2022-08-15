package http

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type HttpGetRequestParams struct {
	Params map[string]string
}

func Get(url, accessToken string, params *HttpGetRequestParams) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	if params != nil {
		query := req.URL.Query()
		for k, v := range params.Params {
			query.Add(k, v)
		}
		req.URL.RawQuery = query.Encode()
	}

	if accessToken != "" {
		bearer := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Add("Authorization", bearer)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func Post(url, accessToken string, data []byte) (map[string]interface{}, error) {
	req, _ := http.NewRequest("POST", url, strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	if accessToken != "" {
		bearer := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Add("Authorization", bearer)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&res)

	return res, nil
}

func Put(url, accessToken string, data []byte) (map[string]interface{}, error) {
	req, _ := http.NewRequest("PUT", url, strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	if accessToken != "" {
		bearer := fmt.Sprintf("Bearer %s", accessToken)
		req.Header.Add("Authorization", bearer)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&res)

	return res, nil
}
