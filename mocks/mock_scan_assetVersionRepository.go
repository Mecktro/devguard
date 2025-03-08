// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// ScanAssetVersionRepository is an autogenerated mock type for the assetVersionRepository type
type ScanAssetVersionRepository struct {
	mock.Mock
}

type ScanAssetVersionRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *ScanAssetVersionRepository) EXPECT() *ScanAssetVersionRepository_Expecter {
	return &ScanAssetVersionRepository_Expecter{mock: &_m.Mock}
}

// FindOrCreate provides a mock function with given fields: assetVersionName, assetID, tag, defaultBranch
func (_m *ScanAssetVersionRepository) FindOrCreate(assetVersionName string, assetID uuid.UUID, tag string, defaultBranch string) (models.AssetVersion, error) {
	ret := _m.Called(assetVersionName, assetID, tag, defaultBranch)

	if len(ret) == 0 {
		panic("no return value specified for FindOrCreate")
	}

	var r0 models.AssetVersion
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string, string) (models.AssetVersion, error)); ok {
		return rf(assetVersionName, assetID, tag, defaultBranch)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string, string) models.AssetVersion); ok {
		r0 = rf(assetVersionName, assetID, tag, defaultBranch)
	} else {
		r0 = ret.Get(0).(models.AssetVersion)
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID, string, string) error); ok {
		r1 = rf(assetVersionName, assetID, tag, defaultBranch)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ScanAssetVersionRepository_FindOrCreate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindOrCreate'
type ScanAssetVersionRepository_FindOrCreate_Call struct {
	*mock.Call
}

// FindOrCreate is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - tag string
//   - defaultBranch string
func (_e *ScanAssetVersionRepository_Expecter) FindOrCreate(assetVersionName interface{}, assetID interface{}, tag interface{}, defaultBranch interface{}) *ScanAssetVersionRepository_FindOrCreate_Call {
	return &ScanAssetVersionRepository_FindOrCreate_Call{Call: _e.mock.On("FindOrCreate", assetVersionName, assetID, tag, defaultBranch)}
}

func (_c *ScanAssetVersionRepository_FindOrCreate_Call) Run(run func(assetVersionName string, assetID uuid.UUID, tag string, defaultBranch string)) *ScanAssetVersionRepository_FindOrCreate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *ScanAssetVersionRepository_FindOrCreate_Call) Return(_a0 models.AssetVersion, _a1 error) *ScanAssetVersionRepository_FindOrCreate_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ScanAssetVersionRepository_FindOrCreate_Call) RunAndReturn(run func(string, uuid.UUID, string, string) (models.AssetVersion, error)) *ScanAssetVersionRepository_FindOrCreate_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, assetVersion
func (_m *ScanAssetVersionRepository) Save(tx *gorm.DB, assetVersion *models.AssetVersion) error {
	ret := _m.Called(tx, assetVersion)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.AssetVersion) error); ok {
		r0 = rf(tx, assetVersion)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ScanAssetVersionRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type ScanAssetVersionRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetVersion *models.AssetVersion
func (_e *ScanAssetVersionRepository_Expecter) Save(tx interface{}, assetVersion interface{}) *ScanAssetVersionRepository_Save_Call {
	return &ScanAssetVersionRepository_Save_Call{Call: _e.mock.On("Save", tx, assetVersion)}
}

func (_c *ScanAssetVersionRepository_Save_Call) Run(run func(tx *gorm.DB, assetVersion *models.AssetVersion)) *ScanAssetVersionRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.AssetVersion))
	})
	return _c
}

func (_c *ScanAssetVersionRepository_Save_Call) Return(_a0 error) *ScanAssetVersionRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ScanAssetVersionRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.AssetVersion) error) *ScanAssetVersionRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// NewScanAssetVersionRepository creates a new instance of ScanAssetVersionRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewScanAssetVersionRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *ScanAssetVersionRepository {
	mock := &ScanAssetVersionRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
