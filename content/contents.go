package content

const (
	Measures_url = "%s/api/measures/search?projectKeys=%s&metricKeys=alert_status,bugs,reliability_rating,vulnerabilities,security_rating,code_smells,sqale_rating,duplicated_lines_density,coverage,ncloc,ncloc_language_distribution"
	Issues_url   = "%s/api/issues/search?componentKeys=%s&s=FILE_LINE&resolved=false&ps=100&facets=owaspTop10,sansTop25,severities,sonarsourceSecurity,types&additionalFields=_all&timeZone=Asia/Shanghai"
	Dingding_url = "https://oapi.dingtalk.com/robot/send?access_token=%s"
	OK_PNG_URL   = "http://s1.ax1x.com/2020/10/29/BGMeTe.png"
	FAIL_PNG_URL = "http://s1.ax1x.com/2020/10/29/BGMZwD.png"
)
