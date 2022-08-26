package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sonar-dingtalk-plugin/content"
)

// dingtalkHandler
func dingtalkHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	sonarRsp := make(map[string]interface{})
	accessToken := r.Form.Get("access_token")
	sonarToken := r.Form.Get("sonar_token")
	if accessToken == "" {
		fmt.Fprintf(w, "access_token不能为空")
	}
	if err := json.NewDecoder(r.Body).Decode(&sonarRsp); err != nil {
		r.Body.Close()
		fmt.Fprintf(w, "解析Sonar参数错误:"+err.Error())
		return
	}

	serverUrl := sonarRsp["serverUrl"]
	projectName := sonarRsp["project"].(map[string]interface{})["name"]
	projectKey := sonarRsp["project"].(map[string]interface{})["key"]
	branch := sonarRsp["branch"].(map[string]interface{})["name"]
	// create http client
	httpClient := &http.Client{
		Transport: &http.Transport{
			// 设置代理 HTTPS_PROXY
			Proxy: http.ProxyFromEnvironment,
		},
	}
	// get measures info

	url := fmt.Sprintf(content.Measures_url,
		serverUrl, projectKey)
	req, _ := http.NewRequest("GET", url, nil)
	if sonarToken != "" {
		req.SetBasicAuth(sonarToken, "")
	}
	measuresRsp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(w, "获取measures失败: "+err.Error())
		return
	}
	measuresObj := make(map[string]interface{})
	if err := json.NewDecoder(measuresRsp.Body).Decode(&measuresObj); err != nil {
		measuresRsp.Body.Close()
		fmt.Fprintf(w, "解析Measures失败: "+err.Error())
		return
	}

	measures := measuresObj["measures"].([]interface{})
	alertStatus := (measures[0].(map[string]interface{}))["value"].(string)
	bugs := (measures[1].(map[string]interface{}))["value"].(string)
	codeSmells := (measures[2].(map[string]interface{}))["value"].(string)
	coverage := (measures[3].(map[string]interface{}))["value"].(string)
	duplicatedLinesDensity := (measures[4].(map[string]interface{}))["value"].(string)

	//ncloc := (measures[5].(map[string]interface{}))["value"].(string)
	//nclocLanguageDistribution := (measures[6].(map[string]interface{}))["value"].(string)
	//neliabilityRating := (measures[7].(map[string]interface{}))["value"].(string)
	//securityRating := (measures[8].(map[string]interface{}))["value"].(string)
	//sqaleRating := (measures[9].(map[string]interface{}))["value"].(string)

	vulnerabilities := (measures[10].(map[string]interface{}))["value"].(string)

	// 成功失败标志
	var picUrl string
	if alertStatus == "OK" {
		picUrl = content.OK_PNG_URL
	} else {
		picUrl = content.FAIL_PNG_URL
	}

	//alertStatus := (measures[0].(map[string]interface{}))["value"].(string)
	//bugs := (measures[1].(map[string]interface{}))["value"].(string)
	//codeSmells := (measures[2].(map[string]interface{}))["value"].(string)
	//coverage := (measures[3].(map[string]interface{}))["value"].(string)
	//duplicatedLinesDensity := (measures[4].(map[string]interface{}))["value"].(string)

	//获取types数量 start--------------------------------------------------------------------------------------
	issuesUrl := fmt.Sprintf(content.Issues_url,
		serverUrl, projectKey)
	issuesReq, _ := http.NewRequest("GET", issuesUrl, nil)
	if sonarToken != "" {
		issuesReq.SetBasicAuth(sonarToken, "")
	}
	issuesRsp, err := httpClient.Do(issuesReq)
	if err != nil {
		fmt.Fprintf(w, "获取issues失败: "+err.Error())
		return
	}
	issuesObj := make(map[string]interface{})
	if err := json.NewDecoder(issuesRsp.Body).Decode(&issuesObj); err != nil {
		issuesRsp.Body.Close()
		fmt.Fprintf(w, "解析issues失败: "+err.Error())
		return
	}
	typeMap := make(map[string]float64)
	facets := issuesObj["facets"].([]interface{})
	fmt.Println("facets == {}", facets)
	for _, facet := range facets {
		serverStr := facet.(map[string]interface{})["property"].(string)
		if "severities" == serverStr {
			valueList := facet.(map[string]interface{})["values"].([]interface{})
			for _, value := range valueList {
				typeName := (value.(map[string]interface{}))["val"].(string)
				typeCount := (value.(map[string]interface{}))["count"].(float64)
				typeMap[typeName] = typeCount
			}
		}
	}
	for key, value := range typeMap {
		fmt.Printf("%s =======> %f\n", key, value)
	}
	//获取types数量 end--------------------------------------------------------------------------------------

	// 发送钉钉消息
	msgUrl := fmt.Sprintf(content.Dingding_url, accessToken)
	messageUrl := fmt.Sprintf("%s/dashboard?id=%s", serverUrl, projectKey)

	link := make(map[string]string)
	link["title"] = fmt.Sprintf("%s[%s]代码扫描报告", projectName, branch)
	link["text"] = fmt.Sprintf("Bugs: %s | 漏洞: %s | 异味: %s\r覆盖率: %s%%\r重复率: %s%%",
		bugs, vulnerabilities, codeSmells, coverage, duplicatedLinesDensity)
	link["messageUrl"] = messageUrl
	link["picUrl"] = picUrl

	param := make(map[string]interface{})
	param["msgtype"] = "link"
	param["link"] = link

	// send dingtalk message
	paramBytes, _ := json.Marshal(param)
	dingTalkRsp, _ := http.Post(msgUrl, "application/json", bytes.NewBuffer(paramBytes))
	dingTalkObj := make(map[string]interface{})
	json.NewDecoder(dingTalkRsp.Body).Decode(&dingTalkObj)
	if dingTalkObj["errcode"].(float64) != 0 {
		fmt.Fprint(w, "消息推送失败，请检查钉钉机器人配置")
		return
	}
	fmt.Fprint(w, "消息推送成功")
}

func findTypes(w http.ResponseWriter, r *http.Request) {

}

func main() {
	http.HandleFunc("/dingtalk", dingtalkHandler)
	log.Println("Server started on port(s): 0.0.0.0:9010 (http)")
	log.Fatal(http.ListenAndServe("0.0.0.0:9010", nil))
}
