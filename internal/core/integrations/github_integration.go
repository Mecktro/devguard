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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v62/github"
	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type githubRepository struct {
	*github.Repository
	GithubAppInstallationID int `json:"githubAppInstallationId"`
}

func (g githubRepository) toRepository() core.Repository {
	return core.Repository{
		ID:    fmt.Sprintf("github:%d:%s", g.GithubAppInstallationID, *g.FullName),
		Label: *g.FullName,
	}
}

type githubAppInstallationRepository interface {
	Save(tx core.DB, model *models.GithubAppInstallation) error
	Read(installationID int) (models.GithubAppInstallation, error)
	FindByOrganizationId(orgID uuid.UUID) ([]models.GithubAppInstallation, error)
	Delete(tx core.DB, installationID int) error
}

type flawRepository interface {
	Read(id string) (models.Flaw, error)
	Save(db core.DB, flaw *models.Flaw) error
	Transaction(fn func(tx core.DB) error) error
	FindByTicketID(tx core.DB, ticketID string) (models.Flaw, error)
	GetOrgFromFlawID(tx core.DB, flawID string) (models.Org, error)
}

type flawEventRepository interface {
	Save(db core.DB, event *models.FlawEvent) error
}

type externalUserRepository interface {
	Save(db core.DB, user *models.ExternalUser) error
	GetDB(tx core.DB) core.DB
	FindByOrgID(tx core.DB, orgID uuid.UUID) ([]models.ExternalUser, error)
}

type assetRepository interface {
	Read(id uuid.UUID) (models.Asset, error)
}

type assetVersionRepository interface {
	Read(assetVersionName string, assetID uuid.UUID) (models.AssetVersion, error)
}

type flawService interface {
	ApplyAndSave(tx core.DB, flaw *models.Flaw, flawEvent *models.FlawEvent) error
}

// wrapper around the github package - which provides only the methods
// we need
type githubClientFacade interface {
	CreateIssue(ctx context.Context, owner string, repo string, issue *github.IssueRequest) (*github.Issue, *github.Response, error)
	CreateIssueComment(ctx context.Context, owner string, repo string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error)
	EditIssue(ctx context.Context, owner string, repo string, number int, issue *github.IssueRequest) (*github.Issue, *github.Response, error)
	EditIssueLabel(ctx context.Context, owner string, repo string, name string, label *github.Label) (*github.Label, *github.Response, error)
}

type githubIntegration struct {
	githubAppInstallationRepository githubAppInstallationRepository
	externalUserRepository          externalUserRepository

	flawRepository         flawRepository
	flawEventRepository    flawEventRepository
	frontendUrl            string
	assetRepository        assetRepository
	assetVersionRepository assetVersionRepository
	flawService            flawService

	githubClientFactory func(repoId string) (githubClientFacade, error)
}

var _ core.ThirdPartyIntegration = &githubIntegration{}

var NoGithubAppInstallationError = fmt.Errorf("no github app installations found")

func NewGithubIntegration(db core.DB) *githubIntegration {
	githubAppInstallationRepository := repositories.NewGithubAppInstallationRepository(db)

	flawRepository := repositories.NewFlawRepository(db)
	flawEventRepository := repositories.NewFlawEventRepository(db)

	frontendUrl := os.Getenv("FRONTEND_URL")
	if frontendUrl == "" {
		panic("FRONTEND_URL is not set")
	}

	return &githubIntegration{
		githubAppInstallationRepository: githubAppInstallationRepository,
		externalUserRepository:          repositories.NewExternalUserRepository(db),

		flawRepository:      flawRepository,
		flawEventRepository: flawEventRepository,
		flawService:         flaw.NewService(flawRepository, flawEventRepository, repositories.NewAssetRepository(db), repositories.NewCVERepository(db)),

		frontendUrl:            frontendUrl,
		assetRepository:        repositories.NewAssetRepository(db),
		assetVersionRepository: repositories.NewAssetVersionRepository(db),

		githubClientFactory: func(repoId string) (githubClientFacade, error) {
			return NewGithubClient(installationIdFromRepositoryID(repoId))
		},
	}
}

func (githubIntegration *githubIntegration) GetID() core.IntegrationID {
	return core.GitHubIntegrationID
}

func (githubIntegration *githubIntegration) IntegrationEnabled(ctx core.Context) bool {
	// check if the github app installation exists in the database
	tenant := core.GetTenant(ctx)
	return len(tenant.GithubAppInstallations) > 0
}

func (githubIntegration *githubIntegration) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	// check if we have integrations
	if !githubIntegration.IntegrationEnabled(ctx) {
		return nil, NoGithubAppInstallationError
	}

	tenant := core.GetTenant(ctx)

	repos := []core.Repository{}
	// check if a github integration exists on that org
	if tenant.GithubAppInstallations != nil {
		// get the github integration
		githubClient, err := newGithubBatchClient(tenant.GithubAppInstallations)
		if err != nil {
			return nil, err
		}

		// get the repositories
		r, err := githubClient.ListRepositories(ctx.QueryParam("search"))
		if err != nil {
			return nil, err
		}

		repos = append(repos, utils.Map(r, func(repo githubRepository) core.Repository {
			return repo.toRepository()
		})...)
		return repos, nil
	}

	return []core.Repository{}, nil
}

func (githubIntegration *githubIntegration) WantsToHandleWebhook(ctx core.Context) bool {
	return true
}

func (githubIntegration *githubIntegration) GetUsers(org models.Org) []core.User {
	users, err := githubIntegration.externalUserRepository.FindByOrgID(nil, org.ID)
	if err != nil {
		slog.Error("could not get users from github", "err", err)
		return nil
	}

	return utils.Map(users, func(user models.ExternalUser) core.User {
		return core.User{
			ID:        user.ID,
			Name:      user.Username,
			AvatarURL: &user.AvatarURL,
		}
	})
}

func (githubIntegration *githubIntegration) HandleWebhook(ctx core.Context) error {

	req := ctx.Request()
	payload, err := github.ValidatePayload(req, []byte(os.Getenv("GITHUB_WEBHOOK_SECRET")))
	if err != nil {
		slog.Debug("could not validate github webhook", "err", err)
		return nil
	}

	event, err := github.ParseWebHook(github.WebHookType(req), payload)
	if err != nil {
		slog.Error("could not parse github webhook", "err", err)
		return err
	}

	switch event := event.(type) {
	case *github.IssueCommentEvent:
		// check if the issue is a devguard issue
		issueId := event.Issue.GetNumber()
		// check if the user is a bot - we do not want to handle bot comments
		if event.Comment.User.GetType() == "Bot" {
			return nil
		}
		// look for a flaw with such a github ticket id
		flaw, err := githubIntegration.flawRepository.FindByTicketID(nil, fmt.Sprintf("github:%d", issueId))
		if err != nil {
			slog.Debug("could not find flaw by ticket id", "err", err, "ticketId", issueId)
			return nil
		}

		// get the asset
		assetVersion, err := githubIntegration.assetVersionRepository.Read(flaw.AssetVersionName, flaw.AssetID)
		if err != nil {
			slog.Error("could not read asset version", "err", err)
			return err
		}

		asset, err := githubIntegration.assetRepository.Read(assetVersion.AssetID)
		if err != nil {
			slog.Error("could not read asset", "err", err)
			return err
		}

		// the issue is a devguard issue.
		// lets check what the comment is about
		comment := event.Comment.GetBody()

		// make sure to save the user - it might be a new user or it might have new values defined.
		// we do not care about any error - and we want speed, thus do it on a goroutine
		go func() {
			org, err := githubIntegration.flawRepository.GetOrgFromFlawID(nil, flaw.ID)
			if err != nil {
				slog.Error("could not get org from flaw id", "err", err)
				return
			}
			// save the user in the database
			user := models.ExternalUser{
				ID:        fmt.Sprintf("github:%d", event.Comment.User.GetID()),
				Username:  event.Comment.User.GetLogin(),
				AvatarURL: event.Comment.User.GetAvatarURL(),
			}

			err = githubIntegration.externalUserRepository.Save(nil, &user)
			if err != nil {
				slog.Error("could not save github user", "err", err)
				return
			}

			if err = githubIntegration.externalUserRepository.GetDB(nil).Model(&user).Association("Organizations").Append([]models.Org{org}); err != nil {
				slog.Error("could not append user to organization", "err", err)
			}
		}()

		// create a new event based on the comment
		flawEvent := createNewFlawEventBasedOnComment(flaw.ID, fmt.Sprintf("github:%d", event.Comment.User.GetID()), comment)

		flawEvent.Apply(&flaw)
		// save the flaw and the event in a transaction
		err = githubIntegration.flawRepository.Transaction(func(tx core.DB) error {
			err := githubIntegration.flawRepository.Save(tx, &flaw)
			if err != nil {
				return err
			}
			err = githubIntegration.flawEventRepository.Save(tx, &flawEvent)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			slog.Error("could not save flaw and event", "err", err)
			return err
		}

		// make sure to update the github issue accordingly
		client, err := githubIntegration.githubClientFactory(utils.SafeDereference(asset.RepositoryID))
		if err != nil {
			slog.Error("could not create github client", "err", err)
			return err
		}

		owner, repo, err := ownerAndRepoFromRepositoryID(utils.SafeDereference(asset.RepositoryID))
		if err != nil {
			slog.Error("could not get owner and repo from repository id", "err", err)
			return err
		}

		switch flawEvent.Type {
		case models.EventTypeAccepted:
			_, _, err = client.EditIssue(context.Background(), owner, repo, issueId, &github.IssueRequest{
				State:  github.String("closed"),
				Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)), "state:accepted"},
			})
			return err
		case models.EventTypeFalsePositive:
			_, _, err = client.EditIssue(context.Background(), owner, repo, issueId, &github.IssueRequest{
				State:  github.String("closed"),
				Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)), "state:false-positive"},
			})
			return err
		case models.EventTypeReopened:
			_, _, err = client.EditIssue(context.Background(), owner, repo, issueId, &github.IssueRequest{
				State:  github.String("open"),
				Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)), "state:open"},
			})
			return err
		}

	case *github.InstallationEvent:
		// check what type of action is being performed
		switch *event.Action {
		case "created":
			slog.Info("new app installation", "installationId", *event.Installation.ID, "senderId", *event.Sender.ID)

			githubAppInstallation := models.GithubAppInstallation{
				InstallationID:                         int(*event.Installation.ID),
				InstallationCreatedWebhookReceivedTime: time.Now(),
				SettingsURL:                            *event.Installation.HTMLURL,
				TargetType:                             *event.Installation.TargetType,
				TargetLogin:                            *event.Installation.Account.Login,
				TargetAvatarURL:                        *event.Installation.Account.AvatarURL,
			}
			// save the new installation to the database
			err := githubIntegration.githubAppInstallationRepository.Save(nil, &githubAppInstallation)
			if err != nil {
				slog.Error("could not save github app installation", "err", err)
				return err
			}
		case "deleted":
			slog.Info("app installation deleted", "installationId", *event.Installation.ID, "senderId", *event.Sender.ID)
			// delete the installation from the database
			err := githubIntegration.githubAppInstallationRepository.Delete(nil, int(*event.Installation.ID))
			if err != nil {
				slog.Error("could not delete github app installation", "err", err)
				return err
			}
		}

	}

	return ctx.JSON(200, "ok")
}

func (githubIntegration *githubIntegration) WantsToFinishInstallation(ctx core.Context) bool {
	return true
}

func (githubIntegration *githubIntegration) FinishInstallation(ctx core.Context) error {
	// get the installation id from the request
	installationID := ctx.QueryParam("installationId")
	if installationID == "" {
		slog.Error("installationId is required")
		return ctx.JSON(400, "installationId is required")
	}

	// check if the org id does match the current organization id, thus the user has access to the organization
	tenant := core.GetTenant(ctx)
	// convert the installation id to an integer
	installationIDInt, err := strconv.Atoi(installationID)
	if err != nil {
		slog.Error("could not convert installationId to int", "err", err)
		return ctx.JSON(400, "could not convert installationId to int")
	}

	// check if the installation id exists in the database
	appInstallation, err := githubIntegration.githubAppInstallationRepository.Read(installationIDInt)
	if err != nil {
		slog.Error("could not read github app installation", "err", err)
		return ctx.JSON(400, "could not read github app installation")
	}

	// check if app installation is already associated with an organization
	if appInstallation.OrgID != nil && *appInstallation.OrgID != tenant.GetID() {
		slog.Error("github app installation already associated with an organization")
		return ctx.JSON(400, "github app installation already associated with an organization")
	} else if appInstallation.OrgID != nil && *appInstallation.OrgID == tenant.GetID() {
		slog.Info("github app installation already associated with the organization")
		return ctx.JSON(200, "ok")
	}

	// add the organization id to the installation
	orgId := tenant.GetID()
	appInstallation.OrgID = &orgId
	// save the installation to the database
	err = githubIntegration.githubAppInstallationRepository.Save(nil, &appInstallation)
	if err != nil {
		slog.Error("could not save github app installation", "err", err)
		return ctx.JSON(400, "could not save github app installation")
	}

	// update the installation with the webhook received time
	// save the installation to the database
	return ctx.JSON(200, "ok")
}

func installationIdFromRepositoryID(repositoryID string) int {
	split := strings.Split(repositoryID, ":")
	if len(split) != 3 {
		return 0
	}
	installationID, err := strconv.Atoi(split[1])
	if err != nil {
		return 0
	}
	return installationID
}

func ownerAndRepoFromRepositoryID(repositoryID string) (string, string, error) {
	split := strings.Split(repositoryID, ":")
	if len(split) != 3 {
		return "", "", fmt.Errorf("could not split repository id")
	}

	split = strings.Split(split[2], "/")
	if len(split) != 2 {
		return "", "", fmt.Errorf("could not split repository id")
	}

	return split[0], split[1], nil
}

func (g *githubIntegration) HandleEvent(event any) error {
	switch event := event.(type) {
	case core.ManualMitigateEvent:
		asset := core.GetAsset(event.Ctx)
		repoId, err := core.GetRepositoryID(event.Ctx)
		if err != nil {
			return nil
		}

		if !strings.HasPrefix(repoId, "github:") {
			// this integration only handles github repositories.
			return nil
		}

		flawId, err := core.GetFlawID(event.Ctx)
		if err != nil {
			return err
		}

		flaw, err := g.flawRepository.Read(flawId)
		if err != nil {
			return err
		}

		// we create a new ticket in github
		client, err := g.githubClientFactory(repoId)
		if err != nil {
			return err
		}
		riskMetrics, vector := risk.RiskCalculation(*flaw.CVE, core.GetEnvironmentalFromAsset(asset))

		exp := risk.Explain(flaw, asset, vector, riskMetrics)
		// print json stringify to the console
		orgSlug, _ := core.GetOrgSlug(event.Ctx)
		projectSlug, _ := core.GetProjectSlug(event.Ctx)
		assetSlug, _ := core.GetAssetSlug(event.Ctx)

		// read the justification from the body
		var justification map[string]string
		err = json.NewDecoder(event.Ctx.Request().Body).Decode(&justification)
		if err != nil {
			return err
		}

		// create a new issue
		issue := &github.IssueRequest{
			Title:  flaw.CVEID,
			Body:   github.String(exp.Markdown(g.frontendUrl, orgSlug, projectSlug, assetSlug) + "\n\n------\n\n" + justification["comment"]),
			Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment))},
		}

		owner, repo, err := ownerAndRepoFromRepositoryID(repoId)
		if err != nil {
			return err
		}

		createdIssue, _, err := client.CreateIssue(context.Background(), owner, repo, issue)
		if err != nil {
			return err
		}

		// todo - we are editing the labels on each call. Actually we only need todo it once
		_, _, err = client.EditIssueLabel(context.Background(), owner, repo, "severity:"+strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)), &github.Label{
			Description: github.String("Severity of the flaw"),
			Color:       github.String(risk.RiskToColor(*flaw.RawRiskAssessment)),
		})
		if err != nil {
			slog.Error("could not update label", "err", err)
		}
		_, _, err = client.EditIssueLabel(context.Background(), owner, repo, "devguard", &github.Label{
			Description: github.String("DevGuard"),
			Color:       github.String("182654"),
		})
		if err != nil {
			slog.Error("could not update label", "err", err)
		}

		// save the issue id to the flaw
		flaw.TicketID = utils.Ptr(fmt.Sprintf("github:%d", createdIssue.GetNumber()))
		flaw.TicketURL = utils.Ptr(createdIssue.GetHTMLURL())
		session := core.GetSession(event.Ctx)
		userID := session.GetUserID()
		// create an event
		flawEvent := models.NewMitigateEvent(flaw.ID, userID, justification["comment"], map[string]any{
			"ticketId":  *flaw.TicketID,
			"ticketUrl": createdIssue.GetHTMLURL(),
		})
		// save the flaw and the event in a transaction
		err = g.flawService.ApplyAndSave(nil, &flaw, &flawEvent)
		// if an error did happen, delete the issue from github
		if err != nil {
			_, _, err := client.EditIssue(context.TODO(), owner, repo, createdIssue.GetNumber(), &github.IssueRequest{
				State: github.String("closed"),
			})
			if err != nil {
				slog.Error("could not delete issue", "err", err)
			}
			return err
		}

		return nil

	case core.FlawEvent:
		ev := event.Event

		asset := core.GetAsset(event.Ctx)
		flaw, err := g.flawRepository.Read(ev.FlawID)

		if err != nil {
			return err
		}

		if flaw.TicketID == nil {
			// we do not have a ticket id - we do not need to do anything
			return nil
		}

		repoId := utils.SafeDereference(asset.RepositoryID)
		if !strings.HasPrefix(repoId, "github:") || !strings.HasPrefix(*flaw.TicketID, "github:") {
			// this integration only handles github repositories.
			return nil
		}
		// we create a new ticket in github
		client, err := g.githubClientFactory(repoId)
		if err != nil {
			return err
		}

		owner, repo, err := ownerAndRepoFromRepositoryID(repoId)
		if err != nil {
			return err
		}

		githubTicketID := strings.TrimPrefix(*flaw.TicketID, "github:")
		githubTicketIDInt, err := strconv.Atoi(githubTicketID)
		if err != nil {
			return err
		}

		members, err := org.FetchMembersOfOrganization(event.Ctx)
		if err != nil {
			return err
		}

		// find the member which created the event
		member, ok := utils.Find(
			members,
			func(member core.User) bool {
				return member.ID == ev.UserID
			},
		)
		if !ok {
			member = core.User{
				Name: "unknown",
			}
		}

		switch ev.Type {
		case models.EventTypeAccepted:
			// if a flaw gets accepted, we close the issue and create a comment with that justification
			_, _, err = client.CreateIssueComment(context.Background(), owner, repo, githubTicketIDInt, &github.IssueComment{
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" accepted the flaw", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}
			_, _, err = client.EditIssue(context.Background(), owner, repo, githubTicketIDInt, &github.IssueRequest{
				State:  github.String("closed"),
				Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)), "state:accepted"},
			})
			return err
		case models.EventTypeFalsePositive:

			_, _, err = client.CreateIssueComment(context.Background(), owner, repo, githubTicketIDInt, &github.IssueComment{
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" marked the flaw as false positive", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

			_, _, err = client.EditIssue(context.Background(), owner, repo, githubTicketIDInt, &github.IssueRequest{
				State:  github.String("closed"),
				Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)), "state:false-positive"},
			})
			return err
		case models.EventTypeReopened:
			_, _, err = client.CreateIssueComment(context.Background(), owner, repo, githubTicketIDInt, &github.IssueComment{
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" reopened the flaw", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

			_, _, err = client.EditIssue(context.Background(), owner, repo, githubTicketIDInt, &github.IssueRequest{
				State:  github.String("open"),
				Labels: &[]string{"devguard", "severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)), "state:open"},
			})
			return err

		case models.EventTypeComment:
			_, _, err = client.CreateIssueComment(context.Background(), owner, repo, githubTicketIDInt, &github.IssueComment{
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" commented on the flaw", utils.SafeDereference(ev.Justification))),
			})
			return err
		}
	}
	return nil
}
