package asset

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/env"
)

type Model struct {
	core.Model
	Name string `json:"name" gorm:"type:varchar(255)"`
	Slug string `json:"slug" gorm:"type:varchar(255);uniqueIndex:idx_app_project_slug;not null;"`

	Envs        []env.Model `json:"envs" gorm:"foreignKey:ApplicationID;constraint:OnDelete:CASCADE;"`
	ProjectID   uuid.UUID   `json:"projectId" gorm:"uniqueIndex:idx_app_project_slug;not null;"`
	Description string      `json:"description" gorm:"type:text"`
}

func (m Model) TableName() string {
	return "applications"
}
