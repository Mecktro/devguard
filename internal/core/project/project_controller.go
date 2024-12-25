// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package project

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
)

type projectRepository interface {
	ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error)
	Update(tx core.DB, project *models.Project) error
	Delete(tx core.DB, projectID uuid.UUID) error
	Create(tx core.DB, project *models.Project) error
	List(projectIds []uuid.UUID, parentId *uuid.UUID, orgId uuid.UUID) ([]models.Project, error)
}

type assetRepository interface {
	GetByProjectID(projectID uuid.UUID) ([]models.Asset, error)
}

type projectService interface {
	ListAllowedProjects(c core.Context) ([]models.Project, error)
}
type Controller struct {
	projectRepository projectRepository
	assetRepository   assetRepository
	projectService    projectService
}

func NewHttpController(repository projectRepository, assetRepository assetRepository, projectService projectService) *Controller {
	return &Controller{
		projectRepository: repository,
		assetRepository:   assetRepository,
		projectService:    projectService,
	}
}

func (p *Controller) Create(c core.Context) error {
	var req CreateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	model := req.ToModel()
	// add the organization id
	model.OrganizationID = core.GetTenant(c).GetID()

	if err := p.projectRepository.Create(nil, &model); err != nil {
		return echo.NewHTTPError(500, "could not create project").WithInternal(err)
	}

	if err := p.bootstrapProject(c, model); err != nil {
		return echo.NewHTTPError(500, "could not bootstrap project").WithInternal(err)
	}

	return c.JSON(200, model)
}

func (p *Controller) Members(c core.Context) error {
	project := core.GetProject(c)
	// get rbac
	rbac := core.GetRBAC(c)

	members, err := rbac.GetAllMembersOfProject(project.ID.String())
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of project").WithInternal(err)
	}

	// get the auth admin client from the context
	authAdminClient := core.GetAuthAdminClient(c)
	// fetch the users from the auth service
	m, _, err := authAdminClient.IdentityAPI.ListIdentitiesExecute(client.IdentityAPIListIdentitiesRequest{}.Ids(members))

	if err != nil {
		return echo.NewHTTPError(500, "could not get members").WithInternal(err)
	}

	users := utils.Map(m, func(i client.Identity) core.User {
		nameMap := i.Traits.(map[string]any)["name"].(map[string]any)
		var name string
		if nameMap != nil {
			if nameMap["first"] != nil {
				name += nameMap["first"].(string)
			}
			if nameMap["last"] != nil {
				name += " " + nameMap["last"].(string)
			}
		}
		return core.User{
			ID:   i.Id,
			Name: name,
		}
	})

	return c.JSON(200, users)
}

func (p *Controller) InviteMember(c core.Context) error {
	project := core.GetProject(c)

	// get rbac
	rbac := core.GetRBAC(c)

	var req inviteToProjectRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	// check if role is valid
	if role := req.Role; role != "admin" && role != "member" {
		return echo.NewHTTPError(400, "invalid role")
	}

	members, err := rbac.GetAllMembersOfOrganization()
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	if !utils.Contains(members, req.UserId) {
		return echo.NewHTTPError(400, "user is not a member of the organization")
	}

	if err := rbac.GrantRoleInProject(req.UserId, req.Role, project.ID.String()); err != nil {
		return err
	}

	return c.NoContent(200)
}

func (p *Controller) RemoveMember(c core.Context) error {
	project := core.GetProject(c)

	// get rbac
	rbac := core.GetRBAC(c)

	var req inviteToProjectRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	// revoke admin and member role
	rbac.RevokeRoleInProject(req.UserId, "admin", project.ID.String())  // nolint:errcheck // we don't care if the user is not an admin
	rbac.RevokeRoleInProject(req.UserId, "member", project.ID.String()) // nolint:errcheck // we don't care if the user is not a member

	return c.NoContent(200)
}

func (p *Controller) ChangeRole(c core.Context) error {
	project := core.GetProject(c)

	// get rbac
	rbac := core.GetRBAC(c)

	var req changeRoleRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	// check if role is valid
	if role := req.Role; role != "admin" && role != "member" {
		return echo.NewHTTPError(400, "invalid role")
	}

	members, err := rbac.GetAllMembersOfOrganization()
	if err != nil {
		return echo.NewHTTPError(500, "could not get members of organization").WithInternal(err)
	}

	if !utils.Contains(members, req.UserId) {
		return echo.NewHTTPError(400, "user is not a member of the organization")
	}

	if err := rbac.RevokeRoleInProject(req.UserId, "admin", project.ID.String()); err != nil {
		return err
	}

	if err := rbac.RevokeRoleInProject(req.UserId, "member", project.ID.String()); err != nil {
		return err
	}

	if err := rbac.GrantRoleInProject(req.UserId, req.Role, project.ID.String()); err != nil {
		return err
	}

	return c.NoContent(200)
}

func (p *Controller) bootstrapProject(c core.Context, project models.Project) error {
	// get the rbac object
	rbac := core.GetRBAC(c)
	// make sure to keep the organization roles in sync
	// let the organization admin role inherit all permissions from the project admin
	if err := rbac.LinkDomainAndProjectRole("admin", "admin", project.ID.String()); err != nil {
		return err
	}

	// give the admin of a project all member permissions
	if err := rbac.InheritProjectRole("admin", "member", project.ID.String()); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "user", []accesscontrol.Action{
		accesscontrol.ActionCreate,
		accesscontrol.ActionDelete,
		accesscontrol.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "asset", []accesscontrol.Action{
		accesscontrol.ActionCreate,
		accesscontrol.ActionDelete,
		accesscontrol.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "admin", "project", []accesscontrol.Action{
		accesscontrol.ActionDelete,
		accesscontrol.ActionUpdate,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "member", "project", []accesscontrol.Action{
		accesscontrol.ActionRead,
	}); err != nil {
		return err
	}

	if err := rbac.AllowRoleInProject(project.ID.String(), "member", "asset", []accesscontrol.Action{
		accesscontrol.ActionRead,
	}); err != nil {
		return err
	}

	// check if there is a parent project - if so, we need to further inherit the roles
	if project.ParentID != nil {
		// make a parent project admin an admin of the child project
		if err := rbac.InheritProjectRolesAcrossProjects(accesscontrol.ProjectRole{
			Role:    "admin",
			Project: (*project.ParentID).String(),
		}, accesscontrol.ProjectRole{
			Role:    "admin",
			Project: project.ID.String(),
		}); err != nil {
			return err
		}

		// make a parent project member a member of the child project
		if err := rbac.InheritProjectRolesAcrossProjects(accesscontrol.ProjectRole{
			Role:    "member",
			Project: (*project.ParentID).String(),
		}, accesscontrol.ProjectRole{
			Role:    "member",
			Project: project.ID.String(),
		}); err != nil {
			return err
		}
	}

	return nil
}

func (p *Controller) Delete(c core.Context) error {
	projectID, err := uuid.Parse(c.Param("projectID"))
	if err != nil {
		return echo.NewHTTPError(400, "invalid project id").WithInternal(err)
	}

	err = p.projectRepository.Delete(nil, projectID)
	if err != nil {
		return err
	}

	return c.NoContent(200)
}

func (p *Controller) Read(c core.Context) error {
	// just get the project from the context
	project := core.GetProject(c)

	// lets fetch the assets related to this project
	assets, err := p.assetRepository.GetByProjectID(project.ID)
	if err != nil {
		return err
	}

	project.Assets = assets

	return c.JSON(200, project)
}

func (p *Controller) List(c core.Context) error {
	// get all projects the user has at least read access to - might be public projects as well
	projects, err := p.projectService.ListAllowedProjects(c)

	if err != nil {
		return err
	}

	return c.JSON(200, projects)
}

func (p *Controller) Update(c core.Context) error {
	req := c.Request().Body
	defer req.Close()
	var patchRequest patchRequest
	err := json.NewDecoder(req).Decode(&patchRequest)
	if err != nil {
		return fmt.Errorf("could not decode request: %w", err)
	}

	project := core.GetProject(c)

	updated := patchRequest.applyToModel(&project)
	if updated {
		err = p.projectRepository.Update(nil, &project)
		if err != nil {
			return fmt.Errorf("could not update project: %w", err)
		}
	}
	return c.JSON(200, project)
}
