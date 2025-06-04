package scan_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
	"gorm.io/gorm/clause"
)

func TestScanning(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")
	controller, _ := initHttpController(t, db)

	// scan the vulnerable sbom
	app := echo.New()
	createCVE2025_46569(db)
	org, project, asset := integration_tests.CreateOrgProjectAndAsset(db)
	setupContext := func(ctx core.Context) {
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetSession(ctx, authSession)
	}

	t.Run("should find a vulnerability in the SBOM", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithVulnerability()

		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-1")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)

		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse

		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)

		assert.Equal(t, 1, response.AmountOpened)
		assert.Equal(t, 0, response.AmountClosed)
		assert.Len(t, response.DependencyVulns, 1)
		assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
	})

	t.Run("should add the scanner id, if the vulnerability is found with another scanner", func(t *testing.T) {
		// we found the CVE - Make sure, that if we scan again but with a different scanner, the scanner ids get updated
		recorder := httptest.NewRecorder()
		// reopen file
		sbomFile := sbomWithVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-2")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, 0, response.AmountOpened) // already detected with other scanner
		assert.Equal(t, 0, response.AmountClosed)
		assert.Len(t, response.DependencyVulns, 1)
		assert.Equal(t, utils.Ptr("CVE-2025-46569"), response.DependencyVulns[0].CVEID)
		// the scanner id should be updated
		assert.Equal(t, "scanner-1 scanner-2", response.DependencyVulns[0].ScannerIDs)
	})

	t.Run("should only return vulnerabilities, which are found by the current scanner", func(t *testing.T) {
		// scan the sbom without the vulnerability
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-3")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)

		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)

		assert.Equal(t, 0, response.AmountOpened) // no new vulnerabilities found
		assert.Equal(t, 0, response.AmountClosed)
		assert.Len(t, response.DependencyVulns, 0) // no vulnerabilities returned
	})

	t.Run("should return amount of closed 1, if the vulnerability is not detected by ANY scanner anymore", func(t *testing.T) {
		// we found the CVE - Make sure, that if we scan again but with a different scanner, the scanner ids get updated
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-1")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)

		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)

		assert.Equal(t, 0, response.AmountOpened)  // no new vulnerabilities found
		assert.Equal(t, 0, response.AmountClosed)  // the vulnerability was not closed - still found by scanner 2
		assert.Len(t, response.DependencyVulns, 0) // no vulnerabilities returned

		sbomFile = sbomWithoutVulnerability()
		req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-2")
		recorder = httptest.NewRecorder()
		ctx = app.NewContext(req, recorder)
		setupContext(ctx)
		err = controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 200, recorder.Code)
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)
		assert.Equal(t, 0, response.AmountOpened)  // no new vulnerabilities found
		assert.Equal(t, 1, response.AmountClosed)  // the vulnerability is finally closed
		assert.Len(t, response.DependencyVulns, 0) // no vulnerabilities returned
	})
}

func TestTicketHandling(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "FRONTEND_URL")
	controller, gitlabClientFacade := initHttpController(t, db)

	// scan the vulnerable sbom
	app := echo.New()
	createCVE2025_46569(db)
	org, project, asset := integration_tests.CreateOrgProjectAndAsset(db)
	setupContext := func(ctx core.Context) {
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetSession(ctx, authSession)
	}

	// create the main asset version
	assetVersion := models.AssetVersion{
		Name:          "main",
		AssetID:       asset.ID,
		DefaultBranch: true,
	}
	err := db.Create(&assetVersion).Error
	assert.Nil(t, err)

	// create a gitlab integration for this org
	gitlabIntegration := models.GitLabIntegration{
		AccessToken: "access-token",
		GitLabUrl:   "https://gitlab.com",
		OrgID:       org.ID,
	}
	err = db.Create(&gitlabIntegration).Error
	assert.Nil(t, err)

	t.Run("should open tickets for vulnerabilities if the risk threshold is exceeded", func(t *testing.T) {
		// update the asset to have a cvss threshold of 7
		asset.CVSSAutomaticTicketThreshold = utils.Ptr(7.0)
		asset.RepositoryID = utils.Ptr(fmt.Sprintf("gitlab:%s:123", gitlabIntegration.ID))
		err := db.Save(&asset).Error
		assert.Nil(t, err)

		// update the cve to exceed this threshold
		cve := models.CVE{
			CVE:  "CVE-2025-46569",
			CVSS: 8.0,
		}
		err = db.Save(&cve).Error
		assert.Nil(t, err)

		// scan the sbom with the vulnerability again
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-4")

		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		// expect there should be a ticket created for the vulnerability
		gitlabClientFacade.On("CreateIssue", mock.Anything, mock.Anything, mock.Anything).Return(&gitlab.Issue{
			IID: 456,
		}, nil, nil).Once()
		gitlabClientFacade.On("CreateIssueComment", mock.Anything, 123, 456, &gitlab.CreateIssueNoteOptions{
			Body: gitlab.Ptr("<devguard> Risk exceeds predefined threshold\n"),
		}).Return(nil, nil, nil).Once()
		// now we expect, that the controller creates a ticket for that vulnerability
		err = controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)
	})

	t.Run("should close existing tickets for vulnerabilities if the vulnerability is fixed", func(t *testing.T) {

		err := db.Clauses(clause.OnConflict{
			UpdateAll: true,
		}).Create(&models.DependencyVuln{
			CVEID:         utils.Ptr("CVE-2025-46569"),
			ComponentPurl: utils.Ptr("pkg:golang/github.com/open-policy-agent/opa@v0.68.0"),
			Vulnerability: models.Vulnerability{
				AssetVersionName: "main",
				ScannerIDs:       "scanner-4",
				State:            models.VulnStateOpen,
				AssetID:          asset.ID,
				TicketID:         utils.Ptr("gitlab:abc/789"),
			},
		}).Error
		assert.Nil(t, err)

		err = db.Save(&asset).Error
		assert.Nil(t, err)

		// scan the sbom with the vulnerability again
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-4")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		// expect there should be a ticket closed for the vulnerability
		gitlabClientFacade.On("EditIssue", mock.Anything, 123, 789, mock.Anything).Return(nil, nil, nil).Once()

		err = controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)
	})

	t.Run("should NOT close existing tickets for vulnerabilities if the vulnerability is still found by a different scanner", func(t *testing.T) {
		// since we mocked CreateIssue, which is responsible of updating the ticket id on a dependency vulnerability, we need to update the dependencyVulnerability manually
		err := db.Clauses(clause.OnConflict{
			UpdateAll: true,
		}).Create(&models.DependencyVuln{
			CVEID:         utils.Ptr("CVE-2025-46569"),
			ComponentPurl: utils.Ptr("pkg:golang/github.com/open-policy-agent/opa@v0.68.0"),
			Vulnerability: models.Vulnerability{
				AssetVersionName: "main",
				ScannerIDs:       "some-other-scanner scanner-4",
				State:            models.VulnStateOpen,
				AssetID:          asset.ID,
				TicketID:         utils.Ptr("ticket-123"),
			},
		}).Error
		assert.Nil(t, err)

		err = db.Save(&asset).Error
		assert.Nil(t, err)

		// scan the sbom with the vulnerability again
		recorder := httptest.NewRecorder()
		sbomFile := sbomWithoutVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-4")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		// DO Not mock the CloseIssue call, because we expect it to not be called
		// thirdPartyIntegration.On("CloseIssue", mock.Anything, "fixed", "repo-123", mock.Anything).Return(nil)

		err = controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)
	})

	t.Run("should not create a ticket, if the vulnerability is in an accepted state", func(t *testing.T) {
		// update the asset to have a cvss threshold of 7
		asset.CVSSAutomaticTicketThreshold = utils.Ptr(7.0)
		asset.RepositoryID = utils.Ptr("repo-123")
		err := db.Save(&asset).Error
		assert.Nil(t, err)

		// update the cve to exceed this threshold
		cve := models.CVE{
			CVE:  "CVE-2025-46569",
			CVSS: 8.0,
		}
		err = db.Save(&cve).Error
		assert.Nil(t, err)

		// create a vulnerability with an accepted state
		vuln := models.DependencyVuln{
			CVEID:         utils.Ptr("CVE-2025-46569"),
			ComponentPurl: utils.Ptr("pkg:golang/github.com/open-policy-agent/opa@v0.68.0"),
			Vulnerability: models.Vulnerability{
				State:            models.VulnStateAccepted,
				ScannerIDs:       "scanner-4",
				AssetVersionName: "main",
				AssetID:          asset.ID,
				TicketID:         nil,
			},
		}
		err = db.Clauses(clause.OnConflict{
			UpdateAll: true,
		}).Create(&vuln).Error
		assert.Nil(t, err)

		recorder := httptest.NewRecorder()
		sbomFile := sbomWithVulnerability()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-4")
		req.Header.Set("X-Asset-Default-Branch", "main")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)

		err = controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)

		assert.Equal(t, 200, recorder.Code)
		var response scan.ScanResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.Nil(t, err)

		assert.Equal(t, 0, response.AmountOpened)  // no new vulnerabilities found
		assert.Equal(t, 0, response.AmountClosed)  // no vulnerabilities closed
		assert.Len(t, response.DependencyVulns, 1) // we expect the accepted vulnerability to be returned
	})
}

func createCVE2025_46569(db core.DB) {
	cve := models.CVE{
		CVE: "CVE-2025-46569",
	}

	err := db.Create(&cve).Error
	if err != nil {
		panic(err)
	}

	affectedComponent := models.AffectedComponent{
		PURL:        "pkg:golang/github.com/open-policy-agent/opa",
		SemverFixed: utils.Ptr("1.4.0"),
	}

	err = db.Create(&affectedComponent).Error
	if err != nil {
		panic(err)
	}

	// create the relationship between the CVE and the affected component
	err = db.Model(&cve).Association("AffectedComponents").Append(&affectedComponent)
	if err != nil {
		panic(err)
	}
}

func sbomWithVulnerability() *os.File {
	file, err := os.Open("./testdata/sbom-with-cve-2025-46569.json")
	if err != nil {
		panic(err)
	}
	return file
}

func sbomWithoutVulnerability() *os.File {
	file, err := os.Open("./testdata/sbom-without-cve-2025-46569.json")
	if err != nil {
		panic(err)
	}
	return file
}

func initHttpController(t *testing.T, db core.DB) (*scan.HttpController, *mocks.GitlabClientFacade) {
	// there are a lot of repositories and services that need to be initialized...
	clientfactory, client := integration_tests.NewTestClientFactory(t)
	gitlabIntegration := gitlabint.NewGitLabIntegration(
		db,
		gitlabint.NewGitLabOauth2Integrations(db),
		mocks.NewRBACProvider(t),
		clientfactory,
	)

	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(gitlabIntegration)
	// Initialize repositories
	assetRepository := repositories.NewAssetRepository(db)
	assetRiskAggregationRepository := repositories.NewAssetRiskHistoryRepository(db)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	statisticsRepository := repositories.NewStatisticsRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	orgRepository := repositories.NewOrgRepository(db)
	cveRepository := repositories.NewCVERepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(db)

	// just to run the migrations
	repositories.NewExploitRepository(db)

	// Initialize services
	dependencyVulnService := vuln.NewService(dependencyVulnRepository, vulnEventRepository, assetRepository, cveRepository, orgRepository, projectRepository, thirdPartyIntegration, assetVersionRepository)
	firstPartyVulnService := vuln.NewFirstPartyVulnService(firstPartyVulnRepository, vulnEventRepository, assetRepository)

	// mock the depsDevService to avoid any external calls during tests
	depsDevService := mocks.NewDepsDevService(t)
	depsDevService.On("GetVersion", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(common.DepsDevVersionResponse{}, nil)

	componentProjectRepository := repositories.NewComponentProjectRepository(db)
	componentService := component.NewComponentService(depsDevService, componentProjectRepository, componentRepository)
	assetVersionService := assetversion.NewService(assetVersionRepository, componentRepository, dependencyVulnRepository, firstPartyVulnRepository, dependencyVulnService, firstPartyVulnService, assetRepository, vulnEventRepository, &componentService)
	statisticsService := statistics.NewService(statisticsRepository, componentRepository, assetRiskAggregationRepository, dependencyVulnRepository, assetVersionRepository, projectRepository, repositories.NewProjectRiskHistoryRepository(db))

	// finally, create the controller
	controller := scan.NewHttpController(db, cveRepository, componentRepository, assetRepository, assetVersionRepository, assetVersionService, statisticsService, dependencyVulnService)
	// do not use concurrency in this test, because we want to test the ticket creation
	controller.FireAndForgetSynchronizer = utils.NewSyncFireAndForgetSynchronizer()
	return controller, client
}
