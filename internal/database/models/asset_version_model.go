package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AssetVersionType string

const (
	AssetVersionBranch AssetVersionType = "branch"
	AssetVersionTag    AssetVersionType = "tag"
)

type AssetVersion struct {
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name string `json:"name" gorm:"primarykey;type:text;not null;"`

	DefaultBranch bool `json:"defaultBranch" gorm:"default:false;"`

	Slug string `json:"slug" gorm:"type:text;uniqueIndex:idx_ver_asset_slug;not null;type:text;"`

	AssetId uuid.UUID `json:"assetId" gorm:"primarykey;uniqueIndex:idx_ver_asset_slug;not null;type:uuid;"`
	Flaws   []Flaw    `json:"flaws" gorm:"foreignKey:AssetVersionID;constraint:OnDelete:CASCADE;"`

	Type AssetVersionType `json:"type" gorm:"type:text;not null;"`

	Components   []ComponentDependency `json:"components" gorm:"hasMany;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	SupplyChains []SupplyChain         `json:"supplyChains" gorm:"foreignKey:AssetVersionID;constraint:OnDelete:CASCADE;"`

	RepositoryID   *string `json:"repositoryId" gorm:"type:text;"` // the id will be prefixed with the provider name, e.g. github:<github app installation id>:123456
	RepositoryName *string `json:"repositoryName" gorm:"type:text;"`

	LastHistoryUpdate *time.Time

	LastSecretScan    *time.Time `json:"lastSecretScan"`
	LastSastScan      *time.Time `json:"lastSastScan"`
	LastScaScan       *time.Time `json:"lastScaScan"`
	LastIacScan       *time.Time `json:"lastIacScan"`
	LastContainerScan *time.Time `json:"lastContainerScan"`
	LastDastScan      *time.Time `json:"lastDastScan"`

	SigningPubKey *string `json:"signingPubKey" gorm:"type:text;"`
}

func (m AssetVersion) TableName() string {
	return "asset_versions"
}
func (m AssetVersion) GetCurrentAssetVersionComponents() []ComponentDependency {
	AssetVersionComponents := make([]ComponentDependency, 0)
	for _, assetComponent := range m.Components {
		if assetComponent.AssetSemverEnd == nil {
			AssetVersionComponents = append(AssetVersionComponents, assetComponent)
		}
	}
	return AssetVersionComponents
}
