package project

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/asset"
)

type Model struct {
	core.Model
	Name           string        `json:"name" gorm:"type:varchar(255)"`
	Assets         []asset.Model `json:"assets" gorm:"foreignKey:ProjectID;constraint:OnDelete:CASCADE;"`
	OrganizationID uuid.UUID     `json:"organizationId" gorm:"uniqueIndex:idx_project_org_slug;not null"`
	Slug           string        `json:"slug" gorm:"type:varchar(255);uniqueIndex:idx_project_org_slug;not null"`
	Description    string        `json:"description" gorm:"type:text"`
}

func (m Model) TableName() string {
	return "projects"
}
