// Code generated by mockery v2.53.0. DO NOT EDIT.

package mocks

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"

	normalize "github.com/l3montree-dev/devguard/internal/core/normalize"

	uuid "github.com/google/uuid"
)

// CoreAssetVersionService is an autogenerated mock type for the AssetVersionService type
type CoreAssetVersionService struct {
	mock.Mock
}

type CoreAssetVersionService_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreAssetVersionService) EXPECT() *CoreAssetVersionService_Expecter {
	return &CoreAssetVersionService_Expecter{mock: &_m.Mock}
}

// BuildSBOM provides a mock function with given fields: assetVersion, version, orgName, components
func (_m *CoreAssetVersionService) BuildSBOM(assetVersion models.AssetVersion, version string, orgName string, components []models.ComponentDependency) *cyclonedx.BOM {
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

// CoreAssetVersionService_BuildSBOM_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BuildSBOM'
type CoreAssetVersionService_BuildSBOM_Call struct {
	*mock.Call
}

// BuildSBOM is a helper method to define mock.On call
//   - assetVersion models.AssetVersion
//   - version string
//   - orgName string
//   - components []models.ComponentDependency
func (_e *CoreAssetVersionService_Expecter) BuildSBOM(assetVersion interface{}, version interface{}, orgName interface{}, components interface{}) *CoreAssetVersionService_BuildSBOM_Call {
	return &CoreAssetVersionService_BuildSBOM_Call{Call: _e.mock.On("BuildSBOM", assetVersion, version, orgName, components)}
}

func (_c *CoreAssetVersionService_BuildSBOM_Call) Run(run func(assetVersion models.AssetVersion, version string, orgName string, components []models.ComponentDependency)) *CoreAssetVersionService_BuildSBOM_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.AssetVersion), args[1].(string), args[2].(string), args[3].([]models.ComponentDependency))
	})
	return _c
}

func (_c *CoreAssetVersionService_BuildSBOM_Call) Return(_a0 *cyclonedx.BOM) *CoreAssetVersionService_BuildSBOM_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreAssetVersionService_BuildSBOM_Call) RunAndReturn(run func(models.AssetVersion, string, string, []models.ComponentDependency) *cyclonedx.BOM) *CoreAssetVersionService_BuildSBOM_Call {
	_c.Call.Return(run)
	return _c
}

// BuildVeX provides a mock function with given fields: asset, assetVersion, version, orgName, components, dependencyVulns
func (_m *CoreAssetVersionService) BuildVeX(asset models.Asset, assetVersion models.AssetVersion, version string, orgName string, components []models.ComponentDependency, dependencyVulns []models.DependencyVuln) *cyclonedx.BOM {
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

// CoreAssetVersionService_BuildVeX_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BuildVeX'
type CoreAssetVersionService_BuildVeX_Call struct {
	*mock.Call
}

// BuildVeX is a helper method to define mock.On call
//   - asset models.Asset
//   - assetVersion models.AssetVersion
//   - version string
//   - orgName string
//   - components []models.ComponentDependency
//   - dependencyVulns []models.DependencyVuln
func (_e *CoreAssetVersionService_Expecter) BuildVeX(asset interface{}, assetVersion interface{}, version interface{}, orgName interface{}, components interface{}, dependencyVulns interface{}) *CoreAssetVersionService_BuildVeX_Call {
	return &CoreAssetVersionService_BuildVeX_Call{Call: _e.mock.On("BuildVeX", asset, assetVersion, version, orgName, components, dependencyVulns)}
}

func (_c *CoreAssetVersionService_BuildVeX_Call) Run(run func(asset models.Asset, assetVersion models.AssetVersion, version string, orgName string, components []models.ComponentDependency, dependencyVulns []models.DependencyVuln)) *CoreAssetVersionService_BuildVeX_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Asset), args[1].(models.AssetVersion), args[2].(string), args[3].(string), args[4].([]models.ComponentDependency), args[5].([]models.DependencyVuln))
	})
	return _c
}

func (_c *CoreAssetVersionService_BuildVeX_Call) Return(_a0 *cyclonedx.BOM) *CoreAssetVersionService_BuildVeX_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreAssetVersionService_BuildVeX_Call) RunAndReturn(run func(models.Asset, models.AssetVersion, string, string, []models.ComponentDependency, []models.DependencyVuln) *cyclonedx.BOM) *CoreAssetVersionService_BuildVeX_Call {
	_c.Call.Return(run)
	return _c
}

// GetAssetVersionsByAssetID provides a mock function with given fields: assetID
func (_m *CoreAssetVersionService) GetAssetVersionsByAssetID(assetID uuid.UUID) ([]models.AssetVersion, error) {
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

// CoreAssetVersionService_GetAssetVersionsByAssetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAssetVersionsByAssetID'
type CoreAssetVersionService_GetAssetVersionsByAssetID_Call struct {
	*mock.Call
}

// GetAssetVersionsByAssetID is a helper method to define mock.On call
//   - assetID uuid.UUID
func (_e *CoreAssetVersionService_Expecter) GetAssetVersionsByAssetID(assetID interface{}) *CoreAssetVersionService_GetAssetVersionsByAssetID_Call {
	return &CoreAssetVersionService_GetAssetVersionsByAssetID_Call{Call: _e.mock.On("GetAssetVersionsByAssetID", assetID)}
}

func (_c *CoreAssetVersionService_GetAssetVersionsByAssetID_Call) Run(run func(assetID uuid.UUID)) *CoreAssetVersionService_GetAssetVersionsByAssetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *CoreAssetVersionService_GetAssetVersionsByAssetID_Call) Return(_a0 []models.AssetVersion, _a1 error) *CoreAssetVersionService_GetAssetVersionsByAssetID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreAssetVersionService_GetAssetVersionsByAssetID_Call) RunAndReturn(run func(uuid.UUID) ([]models.AssetVersion, error)) *CoreAssetVersionService_GetAssetVersionsByAssetID_Call {
	_c.Call.Return(run)
	return _c
}

// HandleFirstPartyVulnResult provides a mock function with given fields: asset, assetVersion, sarifScan, scannerID, userID, doRiskManagement
func (_m *CoreAssetVersionService) HandleFirstPartyVulnResult(asset models.Asset, assetVersion *models.AssetVersion, sarifScan models.SarifResult, scannerID string, userID string, doRiskManagement bool) (int, int, []models.FirstPartyVulnerability, error) {
	ret := _m.Called(asset, assetVersion, sarifScan, scannerID, userID, doRiskManagement)

	if len(ret) == 0 {
		panic("no return value specified for HandleFirstPartyVulnResult")
	}

	var r0 int
	var r1 int
	var r2 []models.FirstPartyVulnerability
	var r3 error
	if rf, ok := ret.Get(0).(func(models.Asset, *models.AssetVersion, models.SarifResult, string, string, bool) (int, int, []models.FirstPartyVulnerability, error)); ok {
		return rf(asset, assetVersion, sarifScan, scannerID, userID, doRiskManagement)
	}
	if rf, ok := ret.Get(0).(func(models.Asset, *models.AssetVersion, models.SarifResult, string, string, bool) int); ok {
		r0 = rf(asset, assetVersion, sarifScan, scannerID, userID, doRiskManagement)
	} else {
		r0 = ret.Get(0).(int)
	}

	if rf, ok := ret.Get(1).(func(models.Asset, *models.AssetVersion, models.SarifResult, string, string, bool) int); ok {
		r1 = rf(asset, assetVersion, sarifScan, scannerID, userID, doRiskManagement)
	} else {
		r1 = ret.Get(1).(int)
	}

	if rf, ok := ret.Get(2).(func(models.Asset, *models.AssetVersion, models.SarifResult, string, string, bool) []models.FirstPartyVulnerability); ok {
		r2 = rf(asset, assetVersion, sarifScan, scannerID, userID, doRiskManagement)
	} else {
		if ret.Get(2) != nil {
			r2 = ret.Get(2).([]models.FirstPartyVulnerability)
		}
	}

	if rf, ok := ret.Get(3).(func(models.Asset, *models.AssetVersion, models.SarifResult, string, string, bool) error); ok {
		r3 = rf(asset, assetVersion, sarifScan, scannerID, userID, doRiskManagement)
	} else {
		r3 = ret.Error(3)
	}

	return r0, r1, r2, r3
}

// CoreAssetVersionService_HandleFirstPartyVulnResult_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleFirstPartyVulnResult'
type CoreAssetVersionService_HandleFirstPartyVulnResult_Call struct {
	*mock.Call
}

// HandleFirstPartyVulnResult is a helper method to define mock.On call
//   - asset models.Asset
//   - assetVersion *models.AssetVersion
//   - sarifScan models.SarifResult
//   - scannerID string
//   - userID string
//   - doRiskManagement bool
func (_e *CoreAssetVersionService_Expecter) HandleFirstPartyVulnResult(asset interface{}, assetVersion interface{}, sarifScan interface{}, scannerID interface{}, userID interface{}, doRiskManagement interface{}) *CoreAssetVersionService_HandleFirstPartyVulnResult_Call {
	return &CoreAssetVersionService_HandleFirstPartyVulnResult_Call{Call: _e.mock.On("HandleFirstPartyVulnResult", asset, assetVersion, sarifScan, scannerID, userID, doRiskManagement)}
}

func (_c *CoreAssetVersionService_HandleFirstPartyVulnResult_Call) Run(run func(asset models.Asset, assetVersion *models.AssetVersion, sarifScan models.SarifResult, scannerID string, userID string, doRiskManagement bool)) *CoreAssetVersionService_HandleFirstPartyVulnResult_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Asset), args[1].(*models.AssetVersion), args[2].(models.SarifResult), args[3].(string), args[4].(string), args[5].(bool))
	})
	return _c
}

func (_c *CoreAssetVersionService_HandleFirstPartyVulnResult_Call) Return(_a0 int, _a1 int, _a2 []models.FirstPartyVulnerability, _a3 error) *CoreAssetVersionService_HandleFirstPartyVulnResult_Call {
	_c.Call.Return(_a0, _a1, _a2, _a3)
	return _c
}

func (_c *CoreAssetVersionService_HandleFirstPartyVulnResult_Call) RunAndReturn(run func(models.Asset, *models.AssetVersion, models.SarifResult, string, string, bool) (int, int, []models.FirstPartyVulnerability, error)) *CoreAssetVersionService_HandleFirstPartyVulnResult_Call {
	_c.Call.Return(run)
	return _c
}

// HandleScanResult provides a mock function with given fields: asset, assetVersion, vulns, scanner, scannerID, userID, doRiskManagement
func (_m *CoreAssetVersionService) HandleScanResult(asset models.Asset, assetVersion *models.AssetVersion, vulns []models.VulnInPackage, scanner string, scannerID string, userID string, doRiskManagement bool) (int, int, []models.DependencyVuln, error) {
	ret := _m.Called(asset, assetVersion, vulns, scanner, scannerID, userID, doRiskManagement)

	if len(ret) == 0 {
		panic("no return value specified for HandleScanResult")
	}

	var r0 int
	var r1 int
	var r2 []models.DependencyVuln
	var r3 error
	if rf, ok := ret.Get(0).(func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, bool) (int, int, []models.DependencyVuln, error)); ok {
		return rf(asset, assetVersion, vulns, scanner, scannerID, userID, doRiskManagement)
	}
	if rf, ok := ret.Get(0).(func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, bool) int); ok {
		r0 = rf(asset, assetVersion, vulns, scanner, scannerID, userID, doRiskManagement)
	} else {
		r0 = ret.Get(0).(int)
	}

	if rf, ok := ret.Get(1).(func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, bool) int); ok {
		r1 = rf(asset, assetVersion, vulns, scanner, scannerID, userID, doRiskManagement)
	} else {
		r1 = ret.Get(1).(int)
	}

	if rf, ok := ret.Get(2).(func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, bool) []models.DependencyVuln); ok {
		r2 = rf(asset, assetVersion, vulns, scanner, scannerID, userID, doRiskManagement)
	} else {
		if ret.Get(2) != nil {
			r2 = ret.Get(2).([]models.DependencyVuln)
		}
	}

	if rf, ok := ret.Get(3).(func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, bool) error); ok {
		r3 = rf(asset, assetVersion, vulns, scanner, scannerID, userID, doRiskManagement)
	} else {
		r3 = ret.Error(3)
	}

	return r0, r1, r2, r3
}

// CoreAssetVersionService_HandleScanResult_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleScanResult'
type CoreAssetVersionService_HandleScanResult_Call struct {
	*mock.Call
}

// HandleScanResult is a helper method to define mock.On call
//   - asset models.Asset
//   - assetVersion *models.AssetVersion
//   - vulns []models.VulnInPackage
//   - scanner string
//   - scannerID string
//   - userID string
//   - doRiskManagement bool
func (_e *CoreAssetVersionService_Expecter) HandleScanResult(asset interface{}, assetVersion interface{}, vulns interface{}, scanner interface{}, scannerID interface{}, userID interface{}, doRiskManagement interface{}) *CoreAssetVersionService_HandleScanResult_Call {
	return &CoreAssetVersionService_HandleScanResult_Call{Call: _e.mock.On("HandleScanResult", asset, assetVersion, vulns, scanner, scannerID, userID, doRiskManagement)}
}

func (_c *CoreAssetVersionService_HandleScanResult_Call) Run(run func(asset models.Asset, assetVersion *models.AssetVersion, vulns []models.VulnInPackage, scanner string, scannerID string, userID string, doRiskManagement bool)) *CoreAssetVersionService_HandleScanResult_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Asset), args[1].(*models.AssetVersion), args[2].([]models.VulnInPackage), args[3].(string), args[4].(string), args[5].(string), args[6].(bool))
	})
	return _c
}

func (_c *CoreAssetVersionService_HandleScanResult_Call) Return(amountOpened int, amountClose int, newState []models.DependencyVuln, err error) *CoreAssetVersionService_HandleScanResult_Call {
	_c.Call.Return(amountOpened, amountClose, newState, err)
	return _c
}

func (_c *CoreAssetVersionService_HandleScanResult_Call) RunAndReturn(run func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, bool) (int, int, []models.DependencyVuln, error)) *CoreAssetVersionService_HandleScanResult_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateSBOM provides a mock function with given fields: assetVersion, scannerID, sbom
func (_m *CoreAssetVersionService) UpdateSBOM(assetVersion models.AssetVersion, scannerID string, sbom normalize.SBOM) error {
	ret := _m.Called(assetVersion, scannerID, sbom)

	if len(ret) == 0 {
		panic("no return value specified for UpdateSBOM")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(models.AssetVersion, string, normalize.SBOM) error); ok {
		r0 = rf(assetVersion, scannerID, sbom)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreAssetVersionService_UpdateSBOM_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateSBOM'
type CoreAssetVersionService_UpdateSBOM_Call struct {
	*mock.Call
}

// UpdateSBOM is a helper method to define mock.On call
//   - assetVersion models.AssetVersion
//   - scannerID string
//   - sbom normalize.SBOM
func (_e *CoreAssetVersionService_Expecter) UpdateSBOM(assetVersion interface{}, scannerID interface{}, sbom interface{}) *CoreAssetVersionService_UpdateSBOM_Call {
	return &CoreAssetVersionService_UpdateSBOM_Call{Call: _e.mock.On("UpdateSBOM", assetVersion, scannerID, sbom)}
}

func (_c *CoreAssetVersionService_UpdateSBOM_Call) Run(run func(assetVersion models.AssetVersion, scannerID string, sbom normalize.SBOM)) *CoreAssetVersionService_UpdateSBOM_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.AssetVersion), args[1].(string), args[2].(normalize.SBOM))
	})
	return _c
}

func (_c *CoreAssetVersionService_UpdateSBOM_Call) Return(_a0 error) *CoreAssetVersionService_UpdateSBOM_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreAssetVersionService_UpdateSBOM_Call) RunAndReturn(run func(models.AssetVersion, string, normalize.SBOM) error) *CoreAssetVersionService_UpdateSBOM_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreAssetVersionService creates a new instance of CoreAssetVersionService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreAssetVersionService(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreAssetVersionService {
	mock := &CoreAssetVersionService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
