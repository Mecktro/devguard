// Code generated by mockery v2.53.0. DO NOT EDIT.

package mocks

import (
	normalize "github.com/l3montree-dev/devguard/internal/core/normalize"
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// ScanAssetVersionService is an autogenerated mock type for the assetVersionService type
type ScanAssetVersionService struct {
	mock.Mock
}

type ScanAssetVersionService_Expecter struct {
	mock *mock.Mock
}

func (_m *ScanAssetVersionService) EXPECT() *ScanAssetVersionService_Expecter {
	return &ScanAssetVersionService_Expecter{mock: &_m.Mock}
}

// HandleFirstPartyVulnResult provides a mock function with given fields: asset, assetVersion, sarifScan, scannerID, userID, doRiskManagement
func (_m *ScanAssetVersionService) HandleFirstPartyVulnResult(asset models.Asset, assetVersion *models.AssetVersion, sarifScan models.SarifResult, scannerID string, userID string, doRiskManagement bool) (int, int, []models.FirstPartyVulnerability, error) {
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

// ScanAssetVersionService_HandleFirstPartyVulnResult_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleFirstPartyVulnResult'
type ScanAssetVersionService_HandleFirstPartyVulnResult_Call struct {
	*mock.Call
}

// HandleFirstPartyVulnResult is a helper method to define mock.On call
//   - asset models.Asset
//   - assetVersion *models.AssetVersion
//   - sarifScan models.SarifResult
//   - scannerID string
//   - userID string
//   - doRiskManagement bool
func (_e *ScanAssetVersionService_Expecter) HandleFirstPartyVulnResult(asset interface{}, assetVersion interface{}, sarifScan interface{}, scannerID interface{}, userID interface{}, doRiskManagement interface{}) *ScanAssetVersionService_HandleFirstPartyVulnResult_Call {
	return &ScanAssetVersionService_HandleFirstPartyVulnResult_Call{Call: _e.mock.On("HandleFirstPartyVulnResult", asset, assetVersion, sarifScan, scannerID, userID, doRiskManagement)}
}

func (_c *ScanAssetVersionService_HandleFirstPartyVulnResult_Call) Run(run func(asset models.Asset, assetVersion *models.AssetVersion, sarifScan models.SarifResult, scannerID string, userID string, doRiskManagement bool)) *ScanAssetVersionService_HandleFirstPartyVulnResult_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Asset), args[1].(*models.AssetVersion), args[2].(models.SarifResult), args[3].(string), args[4].(string), args[5].(bool))
	})
	return _c
}

func (_c *ScanAssetVersionService_HandleFirstPartyVulnResult_Call) Return(_a0 int, _a1 int, _a2 []models.FirstPartyVulnerability, _a3 error) *ScanAssetVersionService_HandleFirstPartyVulnResult_Call {
	_c.Call.Return(_a0, _a1, _a2, _a3)
	return _c
}

func (_c *ScanAssetVersionService_HandleFirstPartyVulnResult_Call) RunAndReturn(run func(models.Asset, *models.AssetVersion, models.SarifResult, string, string, bool) (int, int, []models.FirstPartyVulnerability, error)) *ScanAssetVersionService_HandleFirstPartyVulnResult_Call {
	_c.Call.Return(run)
	return _c
}

// HandleScanResult provides a mock function with given fields: asset, assetVersion, vulns, scanner, version, scannerID, userID, doRiskManagement
func (_m *ScanAssetVersionService) HandleScanResult(asset models.Asset, assetVersion *models.AssetVersion, vulns []models.VulnInPackage, scanner string, version string, scannerID string, userID string, doRiskManagement bool) (int, int, []models.DependencyVuln, error) {
	ret := _m.Called(asset, assetVersion, vulns, scanner, version, scannerID, userID, doRiskManagement)

	if len(ret) == 0 {
		panic("no return value specified for HandleScanResult")
	}

	var r0 int
	var r1 int
	var r2 []models.DependencyVuln
	var r3 error
	if rf, ok := ret.Get(0).(func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, string, bool) (int, int, []models.DependencyVuln, error)); ok {
		return rf(asset, assetVersion, vulns, scanner, version, scannerID, userID, doRiskManagement)
	}
	if rf, ok := ret.Get(0).(func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, string, bool) int); ok {
		r0 = rf(asset, assetVersion, vulns, scanner, version, scannerID, userID, doRiskManagement)
	} else {
		r0 = ret.Get(0).(int)
	}

	if rf, ok := ret.Get(1).(func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, string, bool) int); ok {
		r1 = rf(asset, assetVersion, vulns, scanner, version, scannerID, userID, doRiskManagement)
	} else {
		r1 = ret.Get(1).(int)
	}

	if rf, ok := ret.Get(2).(func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, string, bool) []models.DependencyVuln); ok {
		r2 = rf(asset, assetVersion, vulns, scanner, version, scannerID, userID, doRiskManagement)
	} else {
		if ret.Get(2) != nil {
			r2 = ret.Get(2).([]models.DependencyVuln)
		}
	}

	if rf, ok := ret.Get(3).(func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, string, bool) error); ok {
		r3 = rf(asset, assetVersion, vulns, scanner, version, scannerID, userID, doRiskManagement)
	} else {
		r3 = ret.Error(3)
	}

	return r0, r1, r2, r3
}

// ScanAssetVersionService_HandleScanResult_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleScanResult'
type ScanAssetVersionService_HandleScanResult_Call struct {
	*mock.Call
}

// HandleScanResult is a helper method to define mock.On call
//   - asset models.Asset
//   - assetVersion *models.AssetVersion
//   - vulns []models.VulnInPackage
//   - scanner string
//   - version string
//   - scannerID string
//   - userID string
//   - doRiskManagement bool
func (_e *ScanAssetVersionService_Expecter) HandleScanResult(asset interface{}, assetVersion interface{}, vulns interface{}, scanner interface{}, version interface{}, scannerID interface{}, userID interface{}, doRiskManagement interface{}) *ScanAssetVersionService_HandleScanResult_Call {
	return &ScanAssetVersionService_HandleScanResult_Call{Call: _e.mock.On("HandleScanResult", asset, assetVersion, vulns, scanner, version, scannerID, userID, doRiskManagement)}
}

func (_c *ScanAssetVersionService_HandleScanResult_Call) Run(run func(asset models.Asset, assetVersion *models.AssetVersion, vulns []models.VulnInPackage, scanner string, version string, scannerID string, userID string, doRiskManagement bool)) *ScanAssetVersionService_HandleScanResult_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Asset), args[1].(*models.AssetVersion), args[2].([]models.VulnInPackage), args[3].(string), args[4].(string), args[5].(string), args[6].(string), args[7].(bool))
	})
	return _c
}

func (_c *ScanAssetVersionService_HandleScanResult_Call) Return(amountOpened int, amountClose int, newState []models.DependencyVuln, err error) *ScanAssetVersionService_HandleScanResult_Call {
	_c.Call.Return(amountOpened, amountClose, newState, err)
	return _c
}

func (_c *ScanAssetVersionService_HandleScanResult_Call) RunAndReturn(run func(models.Asset, *models.AssetVersion, []models.VulnInPackage, string, string, string, string, bool) (int, int, []models.DependencyVuln, error)) *ScanAssetVersionService_HandleScanResult_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateSBOM provides a mock function with given fields: asset, scanner, version, sbom
func (_m *ScanAssetVersionService) UpdateSBOM(asset models.AssetVersion, scanner string, version string, sbom normalize.SBOM) error {
	ret := _m.Called(asset, scanner, version, sbom)

	if len(ret) == 0 {
		panic("no return value specified for UpdateSBOM")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(models.AssetVersion, string, string, normalize.SBOM) error); ok {
		r0 = rf(asset, scanner, version, sbom)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ScanAssetVersionService_UpdateSBOM_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateSBOM'
type ScanAssetVersionService_UpdateSBOM_Call struct {
	*mock.Call
}

// UpdateSBOM is a helper method to define mock.On call
//   - asset models.AssetVersion
//   - scanner string
//   - version string
//   - sbom normalize.SBOM
func (_e *ScanAssetVersionService_Expecter) UpdateSBOM(asset interface{}, scanner interface{}, version interface{}, sbom interface{}) *ScanAssetVersionService_UpdateSBOM_Call {
	return &ScanAssetVersionService_UpdateSBOM_Call{Call: _e.mock.On("UpdateSBOM", asset, scanner, version, sbom)}
}

func (_c *ScanAssetVersionService_UpdateSBOM_Call) Run(run func(asset models.AssetVersion, scanner string, version string, sbom normalize.SBOM)) *ScanAssetVersionService_UpdateSBOM_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.AssetVersion), args[1].(string), args[2].(string), args[3].(normalize.SBOM))
	})
	return _c
}

func (_c *ScanAssetVersionService_UpdateSBOM_Call) Return(_a0 error) *ScanAssetVersionService_UpdateSBOM_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ScanAssetVersionService_UpdateSBOM_Call) RunAndReturn(run func(models.AssetVersion, string, string, normalize.SBOM) error) *ScanAssetVersionService_UpdateSBOM_Call {
	_c.Call.Return(run)
	return _c
}

// NewScanAssetVersionService creates a new instance of ScanAssetVersionService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewScanAssetVersionService(t interface {
	mock.TestingT
	Cleanup(func())
}) *ScanAssetVersionService {
	mock := &ScanAssetVersionService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
