// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"

	uuid "github.com/google/uuid"
)

// AssetversionAssetVersionService is an autogenerated mock type for the assetVersionService type
type AssetversionAssetVersionService struct {
	mock.Mock
}

type AssetversionAssetVersionService_Expecter struct {
	mock *mock.Mock
}

func (_m *AssetversionAssetVersionService) EXPECT() *AssetversionAssetVersionService_Expecter {
	return &AssetversionAssetVersionService_Expecter{mock: &_m.Mock}
}

// BuildSBOM provides a mock function with given fields: assetVersion, version, orgName, components
func (_m *AssetversionAssetVersionService) BuildSBOM(assetVersion models.AssetVersion, version string, orgName string, components []models.ComponentDependency) *cyclonedx.BOM {
	ret := _m.Called(assetVersion, version, orgName, components)

	if len(ret) == 0 {
		panic("no return value specified for BuildSBOM")
	}

	var r0 *cyclonedx.BOM
	if rf, ok := ret.Get(0).(func(models.AssetVersion, string, string, []models.ComponentDependency) *cyclonedx.BOM); ok {
		r0 = rf(assetVersion, version, orgName, components)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*cyclonedx.BOM)
		}
	}

	return r0
}

// AssetversionAssetVersionService_BuildSBOM_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BuildSBOM'
type AssetversionAssetVersionService_BuildSBOM_Call struct {
	*mock.Call
}

// BuildSBOM is a helper method to define mock.On call
//   - assetVersion models.AssetVersion
//   - version string
//   - orgName string
//   - components []models.ComponentDependency
func (_e *AssetversionAssetVersionService_Expecter) BuildSBOM(assetVersion interface{}, version interface{}, orgName interface{}, components interface{}) *AssetversionAssetVersionService_BuildSBOM_Call {
	return &AssetversionAssetVersionService_BuildSBOM_Call{Call: _e.mock.On("BuildSBOM", assetVersion, version, orgName, components)}
}

func (_c *AssetversionAssetVersionService_BuildSBOM_Call) Run(run func(assetVersion models.AssetVersion, version string, orgName string, components []models.ComponentDependency)) *AssetversionAssetVersionService_BuildSBOM_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.AssetVersion), args[1].(string), args[2].(string), args[3].([]models.ComponentDependency))
	})
	return _c
}

func (_c *AssetversionAssetVersionService_BuildSBOM_Call) Return(_a0 *cyclonedx.BOM) *AssetversionAssetVersionService_BuildSBOM_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetversionAssetVersionService_BuildSBOM_Call) RunAndReturn(run func(models.AssetVersion, string, string, []models.ComponentDependency) *cyclonedx.BOM) *AssetversionAssetVersionService_BuildSBOM_Call {
	_c.Call.Return(run)
	return _c
}

// BuildVeX provides a mock function with given fields: asset, assetVersion, version, orgName, components, dependencyVulns
func (_m *AssetversionAssetVersionService) BuildVeX(asset models.Asset, assetVersion models.AssetVersion, version string, orgName string, components []models.ComponentDependency, dependencyVulns []models.DependencyVuln) *cyclonedx.BOM {
	ret := _m.Called(asset, assetVersion, version, orgName, components, dependencyVulns)

	if len(ret) == 0 {
		panic("no return value specified for BuildVeX")
	}

	var r0 *cyclonedx.BOM
	if rf, ok := ret.Get(0).(func(models.Asset, models.AssetVersion, string, string, []models.ComponentDependency, []models.DependencyVuln) *cyclonedx.BOM); ok {
		r0 = rf(asset, assetVersion, version, orgName, components, dependencyVulns)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*cyclonedx.BOM)
		}
	}

	return r0
}

// AssetversionAssetVersionService_BuildVeX_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BuildVeX'
type AssetversionAssetVersionService_BuildVeX_Call struct {
	*mock.Call
}

// BuildVeX is a helper method to define mock.On call
//   - asset models.Asset
//   - assetVersion models.AssetVersion
//   - version string
//   - orgName string
//   - components []models.ComponentDependency
//   - dependencyVulns []models.DependencyVuln
func (_e *AssetversionAssetVersionService_Expecter) BuildVeX(asset interface{}, assetVersion interface{}, version interface{}, orgName interface{}, components interface{}, dependencyVulns interface{}) *AssetversionAssetVersionService_BuildVeX_Call {
	return &AssetversionAssetVersionService_BuildVeX_Call{Call: _e.mock.On("BuildVeX", asset, assetVersion, version, orgName, components, dependencyVulns)}
}

func (_c *AssetversionAssetVersionService_BuildVeX_Call) Run(run func(asset models.Asset, assetVersion models.AssetVersion, version string, orgName string, components []models.ComponentDependency, dependencyVulns []models.DependencyVuln)) *AssetversionAssetVersionService_BuildVeX_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Asset), args[1].(models.AssetVersion), args[2].(string), args[3].(string), args[4].([]models.ComponentDependency), args[5].([]models.DependencyVuln))
	})
	return _c
}

func (_c *AssetversionAssetVersionService_BuildVeX_Call) Return(_a0 *cyclonedx.BOM) *AssetversionAssetVersionService_BuildVeX_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *AssetversionAssetVersionService_BuildVeX_Call) RunAndReturn(run func(models.Asset, models.AssetVersion, string, string, []models.ComponentDependency, []models.DependencyVuln) *cyclonedx.BOM) *AssetversionAssetVersionService_BuildVeX_Call {
	_c.Call.Return(run)
	return _c
}

// GetAssetVersionsByAssetID provides a mock function with given fields: assetID
func (_m *AssetversionAssetVersionService) GetAssetVersionsByAssetID(assetID uuid.UUID) ([]models.AssetVersion, error) {
	ret := _m.Called(assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetAssetVersionsByAssetID")
	}

	var r0 []models.AssetVersion
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) ([]models.AssetVersion, error)); ok {
		return rf(assetID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) []models.AssetVersion); ok {
		r0 = rf(assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.AssetVersion)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// AssetversionAssetVersionService_GetAssetVersionsByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetVersionsByAssetID'
type AssetversionAssetVersionService_GetAssetVersionsByAssetID_Call struct {
	*mock.Call
}

// GetAssetVersionsByAssetID is a helper method to define mock.On call
//   - assetID uuid.UUID
func (_e *AssetversionAssetVersionService_Expecter) GetAssetVersionsByAssetID(assetID interface{}) *AssetversionAssetVersionService_GetAssetVersionsByAssetID_Call {
	return &AssetversionAssetVersionService_GetAssetVersionsByAssetID_Call{Call: _e.mock.On("GetAssetVersionsByAssetID", assetID)}
}

func (_c *AssetversionAssetVersionService_GetAssetVersionsByAssetID_Call) Run(run func(assetID uuid.UUID)) *AssetversionAssetVersionService_GetAssetVersionsByAssetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *AssetversionAssetVersionService_GetAssetVersionsByAssetID_Call) Return(_a0 []models.AssetVersion, _a1 error) *AssetversionAssetVersionService_GetAssetVersionsByAssetID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *AssetversionAssetVersionService_GetAssetVersionsByAssetID_Call) RunAndReturn(run func(uuid.UUID) ([]models.AssetVersion, error)) *AssetversionAssetVersionService_GetAssetVersionsByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// NewAssetversionAssetVersionService creates a new instance of AssetversionAssetVersionService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewAssetversionAssetVersionService(t interface {
	mock.TestingT
	Cleanup(func())
}) *AssetversionAssetVersionService {
	mock := &AssetversionAssetVersionService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
