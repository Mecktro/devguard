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

package models

import (
	"time"

	"github.com/google/uuid"
)

type GithubAppInstallation struct {
	InstallationID int `json:"installationId" gorm:"primaryKey"`

	Org   *Org       `json:"org" gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE;"`
	OrgID *uuid.UUID `json:"orgId" gorm:"column:org_id"`

	InstallationCreatedWebhookReceivedTime time.Time `json:"installationCreatedWebhookReceivedTime"`

	SettingsURL string `json:"settingsUrl"`

	TargetType      string `json:"targetType"`
	TargetLogin     string `json:"targetLogin"`
	TargetAvatarURL string `json:"targetAvatarUrl"`
}

func (GithubAppInstallation) TableName() string {
	return "github_app_installations"
}

type GithubUser struct {
	ID            int64  `json:"id" gorm:"primaryKey"`
	Username      string `json:"username"`
	AvatarURL     string `json:"avatarUrl"`
	Organizations []Org  `json:"orgs" gorm:"many2many:github_user_orgs;"`
}

func (GithubUser) TableName() string {
	return "github_users"
}
