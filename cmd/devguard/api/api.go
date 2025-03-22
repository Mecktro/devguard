// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/accesscontrol"

	"github.com/l3montree-dev/devguard/internal/auth"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/compliance"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/dependency_vuln"
	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/intoto"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/project"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/echohttp"
	"github.com/labstack/echo/v4"
)

type assetRepository interface {
	ReadBySlug(projectID uuid.UUID, slug string) (models.Asset, error)
}

type assetVersionRepository interface {
	ReadBySlug(assetID uuid.UUID, slug string) (models.AssetVersion, error)
}

type orgRepository interface {
	ReadBySlug(slugOrId string) (models.Org, error)
}

type projectRepository interface {
	ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error)
}

func accessControlMiddleware(obj accesscontrol.Object, act accesscontrol.Action) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			// get the rbac
			rbac := core.GetRBAC(ctx)
			org := core.GetOrganization(ctx)
			// get the user
			user := core.GetSession(ctx).GetUserID()

			allowed, err := rbac.IsAllowed(user, string(obj), act)
			if err != nil {
				ctx.Response().WriteHeader(500)
				return echo.NewHTTPError(500, "could not determine if the user has access")
			}

			// check if the user has the required role
			if !allowed {
				if org.IsPublic && act == accesscontrol.ActionRead {
					core.SetIsPublicRequest(ctx)
				} else {
					ctx.Response().WriteHeader(403)
					return echo.NewHTTPError(403, "forbidden")
				}
			}

			return next(ctx)
		}
	}
}

func assetMiddleware(repository assetRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		// get the project
		return func(ctx echo.Context) error {

			project := core.GetProject(ctx)

			assetSlug, err := core.GetAssetSlug(ctx)
			if err != nil {
				return echo.NewHTTPError(400, "invalid asset slug")
			}

			asset, err := repository.ReadBySlug(project.GetID(), assetSlug)

			if err != nil {
				return echo.NewHTTPError(404, "could not find asset").WithInternal(err)
			}

			core.SetAsset(ctx, asset)

			return next(ctx)
		}
	}
}

func assetVersionMiddleware(repository assetVersionRepository) func(next echo.HandlerFunc) echo.HandlerFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {

			asset := core.GetAsset(ctx)

			assetVersionSlug, err := core.GetAssetVersionSlug(ctx)
			if err != nil {
				return echo.NewHTTPError(400, "invalid asset version slug")
			}

			assetVersion, err := repository.ReadBySlug(asset.GetID(), assetVersionSlug)

			if err != nil {
				if assetVersionSlug == "default" {
					core.SetAssetVersion(ctx, models.AssetVersion{})

					return next(ctx)
				}
				return echo.NewHTTPError(404, "could not find asset version")
			}

			core.SetAssetVersion(ctx, assetVersion)

			return next(ctx)
		}
	}
}

func projectAccessControlFactory(projectRepository projectRepository) accesscontrol.RBACMiddleware {
	return func(obj accesscontrol.Object, act accesscontrol.Action) core.MiddlewareFunc {
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(ctx core.Context) error {
				// get the rbac
				rbac := core.GetRBAC(ctx)

				// get the user
				user := core.GetSession(ctx).GetUserID()

				// get the project id
				projectSlug, err := core.GetProjectSlug(ctx)
				if err != nil {
					return echo.NewHTTPError(500, "could not get project id")
				}

				// get the project by slug and organization.
				project, err := projectRepository.ReadBySlug(core.GetOrganization(ctx).GetID(), projectSlug)

				if err != nil {
					return echo.NewHTTPError(404, "could not get project")
				}

				allowed, err := rbac.IsAllowedInProject(project.ID.String(), user, string(obj), act)

				if err != nil {
					return echo.NewHTTPError(500, "could not determine if the user has access")
				}

				// check if the user has the required role
				if !allowed {
					if project.IsPublic && act == accesscontrol.ActionRead {
						// allow READ on all objects in the project - if access is public
						core.SetIsPublicRequest(ctx)
					} else {
						return echo.NewHTTPError(403, "forbidden")
					}
				}

				ctx.Set("project", project)

				return next(ctx)
			}
		}
	}
}

func projectAccessControl(projectRepository projectRepository, obj accesscontrol.Object, act accesscontrol.Action) core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {
			// get the rbac
			rbac := core.GetRBAC(ctx)

			// get the user
			user := core.GetSession(ctx).GetUserID()

			// get the project id
			projectSlug, err := core.GetProjectSlug(ctx)
			if err != nil {
				return echo.NewHTTPError(500, "could not get project id")
			}

			// get the project by slug and organization.
			project, err := projectRepository.ReadBySlug(core.GetOrganization(ctx).GetID(), projectSlug)

			if err != nil {
				return echo.NewHTTPError(404, "could not get project")
			}

			allowed, err := rbac.IsAllowedInProject(project.ID.String(), user, string(obj), act)

			if err != nil {
				return echo.NewHTTPError(500, "could not determine if the user has access")
			}

			// check if the user has the required role
			if !allowed {
				// check if public
				if project.IsPublic && act == accesscontrol.ActionRead {
					core.SetIsPublicRequest(ctx)
				} else {
					return echo.NewHTTPError(403, "forbidden")
				}
			}

			ctx.Set("project", project)

			return next(ctx)
		}
	}
}

// this middleware is used to set the project slug parameter based on an X-Asset-ID header.
// it is useful for reusing the projectAccessControl middleware and rely on the rbac to determine if the user has access to an specific asset
func assetNameMiddleware() core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {
			// extract the asset id from the header
			// asset name is <organization_slug>/<project_slug>/<asset_slug>
			assetName := ctx.Request().Header.Get("X-Asset-Name")
			if assetName == "" {
				return echo.NewHTTPError(400, "no asset id provided")
			}
			// split the asset name
			assetParts := strings.Split(assetName, "/")
			if len(assetParts) == 5 {
				// the user probably provided the full url
				// check if projects and assets is part of the asset parts - if so, remove them
				// <organization>/projects/<project>/assets/<asset>
				if assetParts[1] == "projects" && assetParts[3] == "assets" {
					assetParts = []string{assetParts[0], assetParts[2], assetParts[4]}
				}
			}
			if len(assetParts) != 3 {
				return echo.NewHTTPError(400, "invalid asset name")
			}
			// set the project slug
			ctx.Set("projectSlug", assetParts[1])
			ctx.Set("organization", assetParts[0])
			ctx.Set("assetSlug", assetParts[2])
			return next(ctx)
		}
	}
}

func multiOrganizationMiddleware(rbacProvider accesscontrol.RBACProvider, organizationRepo orgRepository) core.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) (err error) {

			// get the organization from the provided context
			organization := core.GetParam(ctx, "organization")
			if organization == "" {
				// if no organization is provided, we can't continue
				slog.Error("no organization provided")
				return ctx.JSON(400, map[string]string{"error": "no organization"})
			}

			// get the organization
			org, err := organizationRepo.ReadBySlug(organization)

			if err != nil {
				slog.Error("organization not found")
				return ctx.JSON(400, map[string]string{"error": "no organization"})
			}

			domainRBAC := rbacProvider.GetDomainRBAC(org.ID.String())

			// check if the user is allowed to access the organization
			session := core.GetSession(ctx)
			allowed := domainRBAC.HasAccess(session.GetUserID())

			if !allowed {
				if org.IsPublic {
					core.SetIsPublicRequest(ctx)
				} else {
					// not allowed and not a public organization
					slog.Error("access denied")
					return ctx.JSON(403, map[string]string{"error": "access denied"})
				}
			}

			// set the organization in the context
			ctx.Set("organization", org)
			// set the RBAC in the context
			ctx.Set("rbac", domainRBAC)

			ctx.Set("orgSlug", organization)
			// continue to the request
			return next(ctx)
		}
	}
}

// @Summary      Get user info
// @Description  Retrieves the user ID from the session
// @Tags         session
// @Produce      json
// @Success      200  {object} object{userId=string}
// @Failure      401  {object}  object{error=string}
// @Router       /whoami/ [get]
func whoami(ctx echo.Context) error {
	return ctx.JSON(200, map[string]string{
		"userId": core.GetSession(ctx).GetUserID(),
	})
}

// @Summary      Health Check
// @Description  Indicating the service is running
// @Tags         health
// @Produce      json
// @Success      200  {string}  string "ok"
// @Router       /health [get]
func health(ctx echo.Context) error {
	return ctx.String(200, "ok")
}

func BuildRouter(db core.DB) *echo.Echo {
	ory := auth.GetOryApiClient(os.Getenv("ORY_KRATOS_PUBLIC"))
	oryAdmin := auth.GetOryApiClient(os.Getenv("ORY_KRATOS_ADMIN"))
	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db)

	if err != nil {
		panic(err)
	}
	githubIntegration := integrations.NewGithubIntegration(db)
	gitlabIntegration := integrations.NewGitLabIntegration(db)
	thirdPartyIntegration := integrations.NewThirdPartyIntegrations(githubIntegration, gitlabIntegration)

	// init all repositories using the provided database
	patRepository := repositories.NewPATRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	assetRiskAggregationRepository := repositories.NewAssetRiskHistoryRepository(db)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	statisticsRepository := repositories.NewStatisticsRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	projectScopedRBAC := projectAccessControlFactory(projectRepository)
	orgRepository := repositories.NewOrgRepository(db)
	cveRepository := repositories.NewCVERepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(db)
	intotoLinkRepository := repositories.NewInTotoLinkRepository(db)
	supplyChainRepository := repositories.NewSupplyChainRepository(db)

	dependencyVulnService := dependency_vuln.NewService(dependencyVulnRepository, vulnEventRepository, assetRepository, cveRepository, orgRepository, projectRepository, thirdPartyIntegration)
	firstPartyVulnService := dependency_vuln.NewFirstPartyVulnService(firstPartyVulnRepository, vulnEventRepository, assetRepository)
	projectService := project.NewService(projectRepository)
	dependencyVulnController := dependency_vuln.NewHttpController(dependencyVulnRepository, dependencyVulnService, projectService)

	vulnEventController := events.NewVulnEventController(vulnEventRepository)

	assetService := asset.NewService(assetRepository, dependencyVulnRepository, dependencyVulnService)
	depsDevService := vulndb.NewDepsDevService()
	componentProjectRepository := repositories.NewComponentProjectRepository(db)
	componentService := component.NewComponentService(&depsDevService, componentProjectRepository, componentRepository)

	assetVersionService := assetversion.NewService(assetVersionRepository, componentRepository, dependencyVulnRepository, firstPartyVulnRepository, dependencyVulnService, firstPartyVulnService, assetRepository, &componentService)
	statisticsService := statistics.NewService(statisticsRepository, componentRepository, assetRiskAggregationRepository, dependencyVulnRepository, assetVersionRepository, projectRepository, repositories.NewProjectRiskHistoryRepository(db))
	invitationRepository := repositories.NewInvitationRepository(db)

	intotoService := intoto.NewInTotoService(casbinRBACProvider, intotoLinkRepository, projectRepository, patRepository, supplyChainRepository)
	// init all http controllers using the repositories
	patController := pat.NewHttpController(patRepository)
	orgController := org.NewHttpController(orgRepository, casbinRBACProvider, projectService, invitationRepository)
	projectController := project.NewHttpController(projectRepository, assetRepository, project.NewService(projectRepository))
	assetController := asset.NewHttpController(assetRepository, assetService)
	scanController := scan.NewHttpController(db, cveRepository, componentRepository, assetRepository, assetVersionRepository, assetVersionService, statisticsService, dependencyVulnService)

	assetVersionController := assetversion.NewAssetVersionController(assetVersionRepository, assetVersionService, dependencyVulnRepository, componentRepository, dependencyVulnService, supplyChainRepository)

	intotoController := intoto.NewHttpController(intotoLinkRepository, supplyChainRepository, patRepository, intotoService)
	componentController := component.NewHTTPController(componentRepository)
	complianceController := compliance.NewHTTPController()

	statisticsController := statistics.NewHttpController(statisticsService, assetRepository, assetVersionRepository, projectService)

	patService := pat.NewPatService(patRepository)

	vulndbController := vulndb.NewHttpController(cveRepository)

	server := echohttp.Server()

	integrationController := integrations.NewIntegrationController()

	apiV1Router := server.Group("/api/v1")

	// this makes the third party integrations available to all controllers
	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {
			core.SetThirdPartyIntegration(ctx, thirdPartyIntegration)
			return next(ctx)
		}
	})

	apiV1Router.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx core.Context) error {
			// set the ory admin client to the context
			core.SetAuthAdminClient(ctx, core.NewAdminClient(oryAdmin))
			return next(ctx)
		}
	})

	apiV1Router.POST("/webhook/", integrationController.HandleWebhook)
	// apply the health route without any session or multi organization middleware
	apiV1Router.GET("/health/", health)

	// everything below this line is protected by the session middleware
	sessionRouter := apiV1Router.Group("", auth.SessionMiddleware(ory, patService))
	// register a simple whoami route for testing purposes
	sessionRouter.GET("/whoami/", whoami)
	sessionRouter.POST("/accept-invitation/", orgController.AcceptInvitation)

	//TODO: change "/scan/" to "/sbom-scan/"
	sessionRouter.POST("/scan/", scanController.ScanDependencyVulnFromProject, assetNameMiddleware(), multiOrganizationMiddleware(casbinRBACProvider, orgRepository), projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate), assetMiddleware(assetRepository))

	sessionRouter.POST("/sarif-scan/", scanController.FirstPartyVulnScan, assetNameMiddleware(), multiOrganizationMiddleware(casbinRBACProvider, orgRepository), projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate), assetMiddleware(assetRepository))

	patRouter := sessionRouter.Group("/pats")
	patRouter.POST("/", patController.Create)
	patRouter.GET("/", patController.List)
	patRouter.DELETE("/:tokenId/", patController.Delete)
	patRouter.POST("/revoke-by-private-key/", patController.RevokeByPrivateKey)

	cveRouter := apiV1Router.Group("/vulndb")
	cveRouter.GET("/", vulndbController.ListPaged)
	cveRouter.GET("/:cveId/", vulndbController.Read)

	orgRouter := sessionRouter.Group("/organizations")

	orgRouter.POST("/", orgController.Create)
	orgRouter.GET("/", orgController.List)

	//Api functions for interacting with an organization  ->  .../organizations/<organization-name>/...
	organizationRouter := orgRouter.Group("/:organization", multiOrganizationMiddleware(casbinRBACProvider, orgRepository))
	organizationRouter.DELETE("/", orgController.Delete, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionDelete))
	organizationRouter.GET("/", orgController.Read, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionRead))

	organizationRouter.PATCH("/", orgController.Update, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionUpdate))

	organizationRouter.GET("/metrics/", orgController.Metrics)
	organizationRouter.GET("/content-tree/", orgController.ContentTree)
	//TODO: change it
	//organizationRouter.GET("/dependency-vulns/", dependencyVulnController.ListByOrgPaged)
	organizationRouter.GET("/flaws/", dependencyVulnController.ListByOrgPaged)

	organizationRouter.GET("/members/", orgController.Members)
	organizationRouter.POST("/members/", orgController.InviteMember, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionUpdate))
	organizationRouter.DELETE("/members/:userId/", orgController.RemoveMember, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionDelete))

	organizationRouter.PUT("/members/:userId/", orgController.ChangeRole, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionUpdate))

	organizationRouter.GET("/integrations/finish-installation/", integrationController.FinishInstallation)

	organizationRouter.POST("/integrations/gitlab/test-and-save/", integrationController.TestAndSaveGitLabIntegration)
	organizationRouter.DELETE("/integrations/gitlab/:gitlab_integration_id/", integrationController.DeleteGitLabAccessToken)
	organizationRouter.GET("/integrations/repositories/", integrationController.
		ListRepositories)
	organizationRouter.GET("/stats/risk-history/", statisticsController.GetOrgRiskHistory)
	organizationRouter.GET("/stats/average-fixing-time/", statisticsController.GetAverageOrgFixingTime)
	//TODO: change it
	//organizationRouter.GET("/stats/dependency-vuln-aggregation-state-and-change/", statisticsController.GetOrgDependencyVulnAggregationStateAndChange)
	organizationRouter.GET("/stats/flaw-aggregation-state-and-change/", statisticsController.GetOrgDependencyVulnAggregationStateAndChange)
	organizationRouter.GET("/stats/risk-distribution/", statisticsController.GetOrgRiskDistribution)

	organizationRouter.GET("/projects/", projectController.List, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionRead))
	organizationRouter.POST("/projects/", projectController.Create, accessControlMiddleware(accesscontrol.ObjectOrganization, accesscontrol.ActionUpdate))

	//Api functions for interacting with a project inside an organization  ->  .../organizations/<organization-name>/projects/<project-name>/...
	projectRouter := organizationRouter.Group("/projects/:projectSlug", projectAccessControl(projectRepository, "project", accesscontrol.ActionRead))
	projectRouter.GET("/", projectController.Read)
	//TODO: change it
	//projectRouter.GET("/dependency-vulns/", dependencyVulnController.ListByProjectPaged)
	projectRouter.GET("/flaws/", dependencyVulnController.ListByProjectPaged)

	projectRouter.PATCH("/", projectController.Update, projectScopedRBAC(accesscontrol.ObjectProject, accesscontrol.ActionUpdate))
	projectRouter.DELETE("/", projectController.Delete, projectScopedRBAC(accesscontrol.ObjectProject, accesscontrol.ActionDelete))

	projectRouter.POST("/assets/", assetController.Create, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionCreate))

	projectRouter.GET("/assets/", assetController.List)

	projectRouter.GET("/stats/risk-distribution/", statisticsController.GetProjectRiskDistribution)
	projectRouter.GET("/stats/risk-history/", statisticsController.GetProjectRiskHistory)
	//TODO: change it
	//projectRouter.GET("/stats/dependency-vuln-aggregation-state-and-change/", statisticsController.GetProjectDependencyVulnAggregationStateAndChange)
	projectRouter.GET("/stats/flaw-aggregation-state-and-change/", statisticsController.GetProjectDependencyVulnAggregationStateAndChange)
	projectRouter.GET("/stats/average-fixing-time/", statisticsController.GetAverageProjectFixingTime)

	projectRouter.GET("/members/", projectController.Members)
	projectRouter.POST("/members/", projectController.InviteMembers, projectScopedRBAC(accesscontrol.ObjectProject, accesscontrol.ActionUpdate))
	projectRouter.DELETE("/members/:userId/", projectController.RemoveMember, projectScopedRBAC(accesscontrol.ObjectProject, accesscontrol.ActionDelete))

	projectRouter.PUT("/members/:userId/", projectController.ChangeRole, projectScopedRBAC(accesscontrol.ObjectProject, accesscontrol.ActionUpdate))

	//Api functions for interacting with an asset inside a project  ->  .../projects/<project-name>/assets/<asset-name>/...
	assetRouter := projectRouter.Group("/assets/:assetSlug", projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionRead), assetMiddleware(assetRepository))
	assetRouter.GET("/", assetController.Read)
	assetRouter.DELETE("/", assetController.Delete, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionDelete))

	assetRouter.GET("/refs/", assetVersionController.GetAssetVersionsByAssetID)

	//Api to scan manually using an uploaded SBOM provided by the user
	assetRouter.POST("/sbom-file/", scanController.ScanSbomFile)

	//TODO: add the projectScopedRBAC middleware to the following routes
	assetVersionRouter := assetRouter.Group("/refs/:assetVersionSlug", assetVersionMiddleware(assetVersionRepository))

	assetVersionRouter.GET("/", assetVersionController.Read)
	assetVersionRouter.DELETE("/", assetVersionController.Delete) //Delete an asset version
	assetVersionRouter.GET("/compliance/", complianceController.Compliance)

	assetVersionRouter.GET("/metrics/", assetVersionController.Metrics)
	assetVersionRouter.GET("/dependency-graph/", assetVersionController.DependencyGraph)
	assetVersionRouter.GET("/affected-components/", assetVersionController.AffectedComponents)
	assetVersionRouter.GET("/sbom.json/", assetVersionController.SBOMJSON)
	assetVersionRouter.GET("/sbom.xml/", assetVersionController.SBOMXML)
	assetVersionRouter.GET("/vex.json/", assetVersionController.VEXJSON)
	assetVersionRouter.GET("/vex.xml/", assetVersionController.VEXXML)

	assetVersionRouter.GET("/stats/component-risk/", statisticsController.GetComponentRisk)
	assetVersionRouter.GET("/stats/risk-distribution/", statisticsController.GetAssetVersionRiskDistribution)
	assetVersionRouter.GET("/stats/risk-history/", statisticsController.GetAssetVersionRiskHistory)
	//TODO: change it
	//assetVersionRouter.GET("/stats/dependency-vuln-count-by-scanner/", statisticsController.GetDependencyVulnCountByScannerId)
	assetVersionRouter.GET("/stats/flaw-count-by-scanner/", statisticsController.GetDependencyVulnCountByScannerId)
	assetVersionRouter.GET("/stats/dependency-count-by-scan-type/", statisticsController.GetDependencyCountPerScanner)

	//TODO: change it
	//assetVersionRouter.GET("/stats/dependency-vuln-aggregation-state-and-change/", statisticsController.GetDependencyVulnAggregationStateAndChange)
	assetVersionRouter.GET("/stats/flaw-aggregation-state-and-change/", statisticsController.GetDependencyVulnAggregationStateAndChange)
	assetVersionRouter.GET("/stats/average-fixing-time/", statisticsController.GetAverageAssetVersionFixingTime)

	assetVersionRouter.GET("/versions/", assetVersionController.Versions)

	assetRouter.POST("/integrations/gitlab/autosetup/", integrationController.AutoSetup, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))
	assetRouter.PATCH("/", assetController.Update, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))

	assetRouter.POST("/signing-key/", assetController.AttachSigningKey, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))

	assetRouter.POST("/in-toto/", intotoController.Create, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))
	assetRouter.GET("/in-toto/root.layout.json/", intotoController.RootLayout)

	assetVersionRouter.GET("/in-toto/:supplyChainId/", intotoController.Read)

	apiV1Router.GET("/verify-supply-chain/", intotoController.VerifySupplyChain)

	assetVersionRouter.GET("/components/", componentController.ListPaged)
	assetVersionRouter.GET("/components/licenses/", componentController.LicenseDistribution)
	//TODO: change it
	//dependencyVulnRouter := assetVersionRouter.Group("/dependency-vulns")
	dependencyVulnRouter := assetVersionRouter.Group("/flaws")
	dependencyVulnRouter.GET("/", dependencyVulnController.ListPaged)
	dependencyVulnRouter.GET("/:dependencyVulnId/", dependencyVulnController.Read)

	dependencyVulnRouter.POST("/:dependencyVulnId/", dependencyVulnController.CreateEvent, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))
	dependencyVulnRouter.POST("/:dependencyVulnId/mitigate/", dependencyVulnController.Mitigate, projectScopedRBAC(accesscontrol.ObjectAsset, accesscontrol.ActionUpdate))

	dependencyVulnRouter.GET("/:dependencyVulnId/events/", vulnEventController.ReadAssetEventsByVulnID)

	routes := server.Routes()
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Path < routes[j].Path
	})
	// print all registered routes
	for _, route := range routes {
		if route.Method != "echo_route_not_found" {
			slog.Info(route.Path, "method", route.Method)
		}
	}
	return server

}

func Start(db core.DB) {
	slog.Error("failed to start server", "err", BuildRouter(db).Start(":8080").Error())
}
