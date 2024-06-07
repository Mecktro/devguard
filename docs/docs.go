// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "Support",
            "url": "https://github.com/l3montree-dev/flawfix/issues"
        },
        "license": {
            "name": "AGPL-3",
            "url": "https://github.com/l3montree-dev/flawfix/blob/main/LICENSE.txt"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/health": {
            "get": {
                "description": "Indicating the service is running",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "health"
                ],
                "summary": "Health Check",
                "responses": {
                    "200": {
                        "description": "ok",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/vulndb": {
            "get": {
                "description": "Get a paginated list of CVEs with optional filtering and sorting",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "CVE"
                ],
                "summary": "List all CVEs with pagination",
                "parameters": [
                    {
                        "type": "integer",
                        "description": "Page number",
                        "name": "page",
                        "in": "query"
                    },
                    {
                        "type": "integer",
                        "description": "Number of items per page",
                        "name": "limit",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Sort by field, e.g. 'sort[cve]=asc",
                        "name": "sort",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Filter query, e.g. 'filterQuery[cvss][is greater than]=4'",
                        "name": "filter",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Confidentiality Requirements (low, medium, high), default is medium",
                        "name": "confidentialityRequirements",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Integrity Requirements (low, medium, high), default is medium",
                        "name": "integrityRequirements",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Availability Requirements (low, medium, high), default is medium",
                        "name": "availabilityRequirements",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "A paginated list of CVEs",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "data": {
                                    "type": "array",
                                    "items": {
                                        "$ref": "#/definitions/github_com_l3montree-dev_flawfix_internal_database_models.CVE"
                                    }
                                },
                                "page": {
                                    "type": "integer"
                                },
                                "pageSize": {
                                    "type": "integer"
                                },
                                "total": {
                                    "type": "integer"
                                }
                            }
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "message": {
                                    "type": "string"
                                }
                            }
                        }
                    }
                }
            }
        },
        "/vulndb/{cveId}/": {
            "get": {
                "description": "Retrieve details of a specific CVE by its ID, including risk and vector calculations",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "CVE"
                ],
                "summary": "Get a specific CVE by ID",
                "parameters": [
                    {
                        "type": "string",
                        "description": "CVE ID",
                        "name": "cveId",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Confidentiality Requirements (low, medium, high), default is medium",
                        "name": "confidentialityRequirements",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Integrity Requirements (low, medium, high), default is medium",
                        "name": "integrityRequirements",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Availability Requirements (low, medium, high), default is medium",
                        "name": "availabilityRequirements",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Details of the specified CVE",
                        "schema": {
                            "$ref": "#/definitions/github_com_l3montree-dev_flawfix_internal_database_models.CVE"
                        }
                    },
                    "500": {
                        "description": "Internal server error",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "message": {
                                    "type": "string"
                                }
                            }
                        }
                    }
                }
            }
        },
        "/whoami/": {
            "get": {
                "description": "Retrieves the user ID from the session",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "session"
                ],
                "summary": "Get user info",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "userId": {
                                    "type": "string"
                                }
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {
                                    "type": "string"
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "github_com_l3montree-dev_flawfix_internal_database_models.AffectedComponent": {
            "type": "object",
            "properties": {
                "cves": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/github_com_l3montree-dev_flawfix_internal_database_models.CVE"
                    }
                },
                "ecosystem": {
                    "type": "string"
                },
                "id": {
                    "type": "string"
                },
                "name": {
                    "type": "string"
                },
                "namespace": {
                    "type": "string"
                },
                "purl": {
                    "type": "string"
                },
                "qualifiers": {
                    "type": "string"
                },
                "scheme": {
                    "type": "string"
                },
                "semver_end": {
                    "type": "string"
                },
                "semver_start": {
                    "type": "string"
                },
                "subpath": {
                    "type": "string"
                },
                "type": {
                    "type": "string"
                },
                "version": {
                    "description": "either version or semver is defined",
                    "type": "string"
                }
            }
        },
        "github_com_l3montree-dev_flawfix_internal_database_models.CPEMatch": {
            "type": "object",
            "properties": {
                "criteria": {
                    "type": "string"
                },
                "cve": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/github_com_l3montree-dev_flawfix_internal_database_models.CVE"
                    }
                },
                "edition": {
                    "type": "string"
                },
                "language": {
                    "type": "string"
                },
                "matchCriteriaId": {
                    "type": "string"
                },
                "other": {
                    "type": "string"
                },
                "part": {
                    "type": "string"
                },
                "product": {
                    "type": "string"
                },
                "swEdition": {
                    "type": "string"
                },
                "targetHw": {
                    "type": "string"
                },
                "targetSw": {
                    "type": "string"
                },
                "update": {
                    "type": "string"
                },
                "vendor": {
                    "type": "string"
                },
                "version": {
                    "type": "string"
                },
                "versionEndExcluding": {
                    "type": "string"
                },
                "versionStartIncluding": {
                    "type": "string"
                },
                "vulnerable": {
                    "type": "boolean"
                }
            }
        },
        "github_com_l3montree-dev_flawfix_internal_database_models.CVE": {
            "type": "object",
            "properties": {
                "affectedComponents": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/github_com_l3montree-dev_flawfix_internal_database_models.AffectedComponent"
                    }
                },
                "attackComplexity": {
                    "type": "string"
                },
                "attackVector": {
                    "type": "string"
                },
                "availabilityImpact": {
                    "type": "string"
                },
                "cisaActionDue": {
                    "type": "string"
                },
                "cisaExploitAdd": {
                    "type": "string"
                },
                "cisaRequiredAction": {
                    "type": "string"
                },
                "cisaVulnerabilityName": {
                    "type": "string"
                },
                "confidentialityImpact": {
                    "type": "string"
                },
                "configurations": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/github_com_l3montree-dev_flawfix_internal_database_models.CPEMatch"
                    }
                },
                "createdAt": {
                    "type": "string"
                },
                "cve": {
                    "type": "string"
                },
                "cvss": {
                    "type": "number"
                },
                "dateLastModified": {
                    "type": "string"
                },
                "datePublished": {
                    "type": "string"
                },
                "description": {
                    "type": "string"
                },
                "epss": {
                    "type": "number"
                },
                "exploitabilityScore": {
                    "type": "number"
                },
                "exploits": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/github_com_l3montree-dev_flawfix_internal_database_models.Exploit"
                    }
                },
                "impactScore": {
                    "type": "number"
                },
                "integrityImpact": {
                    "type": "string"
                },
                "percentile": {
                    "type": "number"
                },
                "privilegesRequired": {
                    "type": "string"
                },
                "references": {
                    "type": "string"
                },
                "risk": {
                    "$ref": "#/definitions/obj.RiskMetrics"
                },
                "scope": {
                    "type": "string"
                },
                "severity": {
                    "$ref": "#/definitions/github_com_l3montree-dev_flawfix_internal_database_models.Severity"
                },
                "updatedAt": {
                    "type": "string"
                },
                "userInteractionRequired": {
                    "type": "string"
                },
                "vector": {
                    "type": "string"
                },
                "weaknesses": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/github_com_l3montree-dev_flawfix_internal_database_models.Weakness"
                    }
                }
            }
        },
        "github_com_l3montree-dev_flawfix_internal_database_models.Exploit": {
            "type": "object",
            "properties": {
                "author": {
                    "type": "string"
                },
                "cve": {
                    "$ref": "#/definitions/github_com_l3montree-dev_flawfix_internal_database_models.CVE"
                },
                "cveID": {
                    "type": "string"
                },
                "description": {
                    "type": "string"
                },
                "id": {
                    "type": "integer"
                },
                "published": {
                    "type": "string"
                },
                "sourceURL": {
                    "type": "string"
                },
                "tags": {
                    "type": "string"
                },
                "type": {
                    "type": "string"
                },
                "updated": {
                    "type": "string"
                },
                "verified": {
                    "type": "boolean"
                }
            }
        },
        "github_com_l3montree-dev_flawfix_internal_database_models.Severity": {
            "type": "string",
            "enum": [
                "critical",
                "high",
                "medium",
                "low",
                "info"
            ],
            "x-enum-varnames": [
                "SeverityCritical",
                "SeverityHigh",
                "SeverityMedium",
                "SeverityLow",
                "SeverityInfo"
            ]
        },
        "github_com_l3montree-dev_flawfix_internal_database_models.Weakness": {
            "type": "object",
            "properties": {
                "cve": {
                    "$ref": "#/definitions/github_com_l3montree-dev_flawfix_internal_database_models.CVE"
                },
                "cwe": {
                    "type": "string"
                },
                "source": {
                    "type": "string"
                },
                "type": {
                    "type": "string"
                }
            }
        },
        "obj.RiskMetrics": {
            "type": "object",
            "properties": {
                "baseScore": {
                    "type": "number"
                },
                "withEnvironment": {
                    "type": "number"
                },
                "withEnvironmentAndThreatIntelligence": {
                    "type": "number"
                },
                "withThreatIntelligence": {
                    "type": "number"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "v1",
	Host:             "localhost:8080",
	BasePath:         "/api/v1",
	Schemes:          []string{},
	Title:            "FlawFix API",
	Description:      "FlawFix API",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
