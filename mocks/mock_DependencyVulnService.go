// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// DependencyVulnService is an autogenerated mock type for the DependencyVulnService type
type DependencyVulnService struct {
	mock.Mock
}

type DependencyVulnService_Expecter struct {
	mock *mock.Mock
}

func (_m *DependencyVulnService) EXPECT() *DependencyVulnService_Expecter {
	return &DependencyVulnService_Expecter{mock: &_m.Mock}
}

// CloseIssuesAsFixed provides a mock function with given fields: asset, vulnList
func (_m *DependencyVulnService) CloseIssuesAsFixed(asset models.Asset, vulnList []models.DependencyVuln) error {
	ret := _m.Called(asset, vulnList)

	if len(ret) == 0 {
		panic("no return value specified for CloseIssuesAsFixed")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(models.Asset, []models.DependencyVuln) error); ok {
		r0 = rf(asset, vulnList)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnService_CloseIssuesAsFixed_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CloseIssuesAsFixed'
type DependencyVulnService_CloseIssuesAsFixed_Call struct {
	*mock.Call
}

// CloseIssuesAsFixed is a helper method to define mock.On call
//   - asset models.Asset
//   - vulnList []models.DependencyVuln
func (_e *DependencyVulnService_Expecter) CloseIssuesAsFixed(asset interface{}, vulnList interface{}) *DependencyVulnService_CloseIssuesAsFixed_Call {
	return &DependencyVulnService_CloseIssuesAsFixed_Call{Call: _e.mock.On("CloseIssuesAsFixed", asset, vulnList)}
}

func (_c *DependencyVulnService_CloseIssuesAsFixed_Call) Run(run func(asset models.Asset, vulnList []models.DependencyVuln)) *DependencyVulnService_CloseIssuesAsFixed_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Asset), args[1].([]models.DependencyVuln))
	})
	return _c
}

func (_c *DependencyVulnService_CloseIssuesAsFixed_Call) Return(_a0 error) *DependencyVulnService_CloseIssuesAsFixed_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnService_CloseIssuesAsFixed_Call) RunAndReturn(run func(models.Asset, []models.DependencyVuln) error) *DependencyVulnService_CloseIssuesAsFixed_Call {
	_c.Call.Return(run)
	return _c
}

// CreateIssuesForVulnsIfThresholdExceeded provides a mock function with given fields: asset, vulnList
func (_m *DependencyVulnService) CreateIssuesForVulnsIfThresholdExceeded(asset models.Asset, vulnList []models.DependencyVuln) error {
	ret := _m.Called(asset, vulnList)

	if len(ret) == 0 {
		panic("no return value specified for CreateIssuesForVulnsIfThresholdExceeded")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(models.Asset, []models.DependencyVuln) error); ok {
		r0 = rf(asset, vulnList)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnService_CreateIssuesForVulnsIfThresholdExceeded_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateIssuesForVulnsIfThresholdExceeded'
type DependencyVulnService_CreateIssuesForVulnsIfThresholdExceeded_Call struct {
	*mock.Call
}

// CreateIssuesForVulnsIfThresholdExceeded is a helper method to define mock.On call
//   - asset models.Asset
//   - vulnList []models.DependencyVuln
func (_e *DependencyVulnService_Expecter) CreateIssuesForVulnsIfThresholdExceeded(asset interface{}, vulnList interface{}) *DependencyVulnService_CreateIssuesForVulnsIfThresholdExceeded_Call {
	return &DependencyVulnService_CreateIssuesForVulnsIfThresholdExceeded_Call{Call: _e.mock.On("CreateIssuesForVulnsIfThresholdExceeded", asset, vulnList)}
}

func (_c *DependencyVulnService_CreateIssuesForVulnsIfThresholdExceeded_Call) Run(run func(asset models.Asset, vulnList []models.DependencyVuln)) *DependencyVulnService_CreateIssuesForVulnsIfThresholdExceeded_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Asset), args[1].([]models.DependencyVuln))
	})
	return _c
}

func (_c *DependencyVulnService_CreateIssuesForVulnsIfThresholdExceeded_Call) Return(_a0 error) *DependencyVulnService_CreateIssuesForVulnsIfThresholdExceeded_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnService_CreateIssuesForVulnsIfThresholdExceeded_Call) RunAndReturn(run func(models.Asset, []models.DependencyVuln) error) *DependencyVulnService_CreateIssuesForVulnsIfThresholdExceeded_Call {
	_c.Call.Return(run)
	return _c
}

// RecalculateRawRiskAssessment provides a mock function with given fields: tx, responsible, dependencyVulns, justification, asset
func (_m *DependencyVulnService) RecalculateRawRiskAssessment(tx *gorm.DB, responsible string, dependencyVulns []models.DependencyVuln, justification string, asset models.Asset) error {
	ret := _m.Called(tx, responsible, dependencyVulns, justification, asset)

	if len(ret) == 0 {
		panic("no return value specified for RecalculateRawRiskAssessment")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.DependencyVuln, string, models.Asset) error); ok {
		r0 = rf(tx, responsible, dependencyVulns, justification, asset)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnService_RecalculateRawRiskAssessment_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RecalculateRawRiskAssessment'
type DependencyVulnService_RecalculateRawRiskAssessment_Call struct {
	*mock.Call
}

// RecalculateRawRiskAssessment is a helper method to define mock.On call
//   - tx *gorm.DB
//   - responsible string
//   - dependencyVulns []models.DependencyVuln
//   - justification string
//   - asset models.Asset
func (_e *DependencyVulnService_Expecter) RecalculateRawRiskAssessment(tx interface{}, responsible interface{}, dependencyVulns interface{}, justification interface{}, asset interface{}) *DependencyVulnService_RecalculateRawRiskAssessment_Call {
	return &DependencyVulnService_RecalculateRawRiskAssessment_Call{Call: _e.mock.On("RecalculateRawRiskAssessment", tx, responsible, dependencyVulns, justification, asset)}
}

func (_c *DependencyVulnService_RecalculateRawRiskAssessment_Call) Run(run func(tx *gorm.DB, responsible string, dependencyVulns []models.DependencyVuln, justification string, asset models.Asset)) *DependencyVulnService_RecalculateRawRiskAssessment_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.DependencyVuln), args[3].(string), args[4].(models.Asset))
	})
	return _c
}

func (_c *DependencyVulnService_RecalculateRawRiskAssessment_Call) Return(_a0 error) *DependencyVulnService_RecalculateRawRiskAssessment_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnService_RecalculateRawRiskAssessment_Call) RunAndReturn(run func(*gorm.DB, string, []models.DependencyVuln, string, models.Asset) error) *DependencyVulnService_RecalculateRawRiskAssessment_Call {
	_c.Call.Return(run)
	return _c
}

// ShouldCreateIssues provides a mock function with given fields: assetVersion
func (_m *DependencyVulnService) ShouldCreateIssues(assetVersion models.AssetVersion) bool {
	ret := _m.Called(assetVersion)

	if len(ret) == 0 {
		panic("no return value specified for ShouldCreateIssues")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(models.AssetVersion) bool); ok {
		r0 = rf(assetVersion)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// DependencyVulnService_ShouldCreateIssues_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ShouldCreateIssues'
type DependencyVulnService_ShouldCreateIssues_Call struct {
	*mock.Call
}

// ShouldCreateIssues is a helper method to define mock.On call
//   - assetVersion models.AssetVersion
func (_e *DependencyVulnService_Expecter) ShouldCreateIssues(assetVersion interface{}) *DependencyVulnService_ShouldCreateIssues_Call {
	return &DependencyVulnService_ShouldCreateIssues_Call{Call: _e.mock.On("ShouldCreateIssues", assetVersion)}
}

func (_c *DependencyVulnService_ShouldCreateIssues_Call) Run(run func(assetVersion models.AssetVersion)) *DependencyVulnService_ShouldCreateIssues_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.AssetVersion))
	})
	return _c
}

func (_c *DependencyVulnService_ShouldCreateIssues_Call) Return(_a0 bool) *DependencyVulnService_ShouldCreateIssues_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnService_ShouldCreateIssues_Call) RunAndReturn(run func(models.AssetVersion) bool) *DependencyVulnService_ShouldCreateIssues_Call {
	_c.Call.Return(run)
	return _c
}

// SyncTickets provides a mock function with given fields: assetVersion
func (_m *DependencyVulnService) SyncTickets(assetVersion models.Asset) error {
	ret := _m.Called(assetVersion)

	if len(ret) == 0 {
		panic("no return value specified for SyncTickets")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(models.Asset) error); ok {
		r0 = rf(assetVersion)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnService_SyncTickets_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SyncTickets'
type DependencyVulnService_SyncTickets_Call struct {
	*mock.Call
}

// SyncTickets is a helper method to define mock.On call
//   - assetVersion models.Asset
func (_e *DependencyVulnService_Expecter) SyncTickets(assetVersion interface{}) *DependencyVulnService_SyncTickets_Call {
	return &DependencyVulnService_SyncTickets_Call{Call: _e.mock.On("SyncTickets", assetVersion)}
}

func (_c *DependencyVulnService_SyncTickets_Call) Run(run func(assetVersion models.Asset)) *DependencyVulnService_SyncTickets_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Asset))
	})
	return _c
}

func (_c *DependencyVulnService_SyncTickets_Call) Return(_a0 error) *DependencyVulnService_SyncTickets_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnService_SyncTickets_Call) RunAndReturn(run func(models.Asset) error) *DependencyVulnService_SyncTickets_Call {
	_c.Call.Return(run)
	return _c
}

// UpdateDependencyVulnState provides a mock function with given fields: tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName
func (_m *DependencyVulnService) UpdateDependencyVulnState(tx *gorm.DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, statusType string, justification string, assetVersionName string) (models.VulnEvent, error) {
	ret := _m.Called(tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName)

	if len(ret) == 0 {
		panic("no return value specified for UpdateDependencyVulnState")
	}

	var r0 models.VulnEvent
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, string, *models.DependencyVuln, string, string, string) (models.VulnEvent, error)); ok {
		return rf(tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID, string, *models.DependencyVuln, string, string, string) models.VulnEvent); ok {
		r0 = rf(tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName)
	} else {
		r0 = ret.Get(0).(models.VulnEvent)
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, uuid.UUID, string, *models.DependencyVuln, string, string, string) error); ok {
		r1 = rf(tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DependencyVulnService_UpdateDependencyVulnState_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateDependencyVulnState'
type DependencyVulnService_UpdateDependencyVulnState_Call struct {
	*mock.Call
}

// UpdateDependencyVulnState is a helper method to define mock.On call
//   - tx *gorm.DB
//   - assetID uuid.UUID
//   - userID string
//   - dependencyVuln *models.DependencyVuln
//   - statusType string
//   - justification string
//   - assetVersionName string
func (_e *DependencyVulnService_Expecter) UpdateDependencyVulnState(tx interface{}, assetID interface{}, userID interface{}, dependencyVuln interface{}, statusType interface{}, justification interface{}, assetVersionName interface{}) *DependencyVulnService_UpdateDependencyVulnState_Call {
	return &DependencyVulnService_UpdateDependencyVulnState_Call{Call: _e.mock.On("UpdateDependencyVulnState", tx, assetID, userID, dependencyVuln, statusType, justification, assetVersionName)}
}

func (_c *DependencyVulnService_UpdateDependencyVulnState_Call) Run(run func(tx *gorm.DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, statusType string, justification string, assetVersionName string)) *DependencyVulnService_UpdateDependencyVulnState_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID), args[2].(string), args[3].(*models.DependencyVuln), args[4].(string), args[5].(string), args[6].(string))
	})
	return _c
}

func (_c *DependencyVulnService_UpdateDependencyVulnState_Call) Return(_a0 models.VulnEvent, _a1 error) *DependencyVulnService_UpdateDependencyVulnState_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *DependencyVulnService_UpdateDependencyVulnState_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID, string, *models.DependencyVuln, string, string, string) (models.VulnEvent, error)) *DependencyVulnService_UpdateDependencyVulnState_Call {
	_c.Call.Return(run)
	return _c
}

// UserDetectedDependencyVulnWithAnotherScanner provides a mock function with given fields: tx, vulnerabilities, userID, scannerID
func (_m *DependencyVulnService) UserDetectedDependencyVulnWithAnotherScanner(tx *gorm.DB, vulnerabilities []models.DependencyVuln, userID string, scannerID string) error {
	ret := _m.Called(tx, vulnerabilities, userID, scannerID)

	if len(ret) == 0 {
		panic("no return value specified for UserDetectedDependencyVulnWithAnotherScanner")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.DependencyVuln, string, string) error); ok {
		r0 = rf(tx, vulnerabilities, userID, scannerID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnService_UserDetectedDependencyVulnWithAnotherScanner_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserDetectedDependencyVulnWithAnotherScanner'
type DependencyVulnService_UserDetectedDependencyVulnWithAnotherScanner_Call struct {
	*mock.Call
}

// UserDetectedDependencyVulnWithAnotherScanner is a helper method to define mock.On call
//   - tx *gorm.DB
//   - vulnerabilities []models.DependencyVuln
//   - userID string
//   - scannerID string
func (_e *DependencyVulnService_Expecter) UserDetectedDependencyVulnWithAnotherScanner(tx interface{}, vulnerabilities interface{}, userID interface{}, scannerID interface{}) *DependencyVulnService_UserDetectedDependencyVulnWithAnotherScanner_Call {
	return &DependencyVulnService_UserDetectedDependencyVulnWithAnotherScanner_Call{Call: _e.mock.On("UserDetectedDependencyVulnWithAnotherScanner", tx, vulnerabilities, userID, scannerID)}
}

func (_c *DependencyVulnService_UserDetectedDependencyVulnWithAnotherScanner_Call) Run(run func(tx *gorm.DB, vulnerabilities []models.DependencyVuln, userID string, scannerID string)) *DependencyVulnService_UserDetectedDependencyVulnWithAnotherScanner_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.DependencyVuln), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *DependencyVulnService_UserDetectedDependencyVulnWithAnotherScanner_Call) Return(_a0 error) *DependencyVulnService_UserDetectedDependencyVulnWithAnotherScanner_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnService_UserDetectedDependencyVulnWithAnotherScanner_Call) RunAndReturn(run func(*gorm.DB, []models.DependencyVuln, string, string) error) *DependencyVulnService_UserDetectedDependencyVulnWithAnotherScanner_Call {
	_c.Call.Return(run)
	return _c
}

// UserDetectedDependencyVulns provides a mock function with given fields: tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement
func (_m *DependencyVulnService) UserDetectedDependencyVulns(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool) error {
	ret := _m.Called(tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)

	if len(ret) == 0 {
		panic("no return value specified for UserDetectedDependencyVulns")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.DependencyVuln, models.AssetVersion, models.Asset, bool) error); ok {
		r0 = rf(tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnService_UserDetectedDependencyVulns_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserDetectedDependencyVulns'
type DependencyVulnService_UserDetectedDependencyVulns_Call struct {
	*mock.Call
}

// UserDetectedDependencyVulns is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - dependencyVulns []models.DependencyVuln
//   - assetVersion models.AssetVersion
//   - asset models.Asset
//   - doRiskManagement bool
func (_e *DependencyVulnService_Expecter) UserDetectedDependencyVulns(tx interface{}, userID interface{}, dependencyVulns interface{}, assetVersion interface{}, asset interface{}, doRiskManagement interface{}) *DependencyVulnService_UserDetectedDependencyVulns_Call {
	return &DependencyVulnService_UserDetectedDependencyVulns_Call{Call: _e.mock.On("UserDetectedDependencyVulns", tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)}
}

func (_c *DependencyVulnService_UserDetectedDependencyVulns_Call) Run(run func(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool)) *DependencyVulnService_UserDetectedDependencyVulns_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.DependencyVuln), args[3].(models.AssetVersion), args[4].(models.Asset), args[5].(bool))
	})
	return _c
}

func (_c *DependencyVulnService_UserDetectedDependencyVulns_Call) Return(_a0 error) *DependencyVulnService_UserDetectedDependencyVulns_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnService_UserDetectedDependencyVulns_Call) RunAndReturn(run func(*gorm.DB, string, []models.DependencyVuln, models.AssetVersion, models.Asset, bool) error) *DependencyVulnService_UserDetectedDependencyVulns_Call {
	_c.Call.Return(run)
	return _c
}

// UserDidNotDetectDependencyVulnWithScannerAnymore provides a mock function with given fields: tx, vulnerabilities, userID, scannerID
func (_m *DependencyVulnService) UserDidNotDetectDependencyVulnWithScannerAnymore(tx *gorm.DB, vulnerabilities []models.DependencyVuln, userID string, scannerID string) error {
	ret := _m.Called(tx, vulnerabilities, userID, scannerID)

	if len(ret) == 0 {
		panic("no return value specified for UserDidNotDetectDependencyVulnWithScannerAnymore")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.DependencyVuln, string, string) error); ok {
		r0 = rf(tx, vulnerabilities, userID, scannerID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnService_UserDidNotDetectDependencyVulnWithScannerAnymore_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserDidNotDetectDependencyVulnWithScannerAnymore'
type DependencyVulnService_UserDidNotDetectDependencyVulnWithScannerAnymore_Call struct {
	*mock.Call
}

// UserDidNotDetectDependencyVulnWithScannerAnymore is a helper method to define mock.On call
//   - tx *gorm.DB
//   - vulnerabilities []models.DependencyVuln
//   - userID string
//   - scannerID string
func (_e *DependencyVulnService_Expecter) UserDidNotDetectDependencyVulnWithScannerAnymore(tx interface{}, vulnerabilities interface{}, userID interface{}, scannerID interface{}) *DependencyVulnService_UserDidNotDetectDependencyVulnWithScannerAnymore_Call {
	return &DependencyVulnService_UserDidNotDetectDependencyVulnWithScannerAnymore_Call{Call: _e.mock.On("UserDidNotDetectDependencyVulnWithScannerAnymore", tx, vulnerabilities, userID, scannerID)}
}

func (_c *DependencyVulnService_UserDidNotDetectDependencyVulnWithScannerAnymore_Call) Run(run func(tx *gorm.DB, vulnerabilities []models.DependencyVuln, userID string, scannerID string)) *DependencyVulnService_UserDidNotDetectDependencyVulnWithScannerAnymore_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.DependencyVuln), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *DependencyVulnService_UserDidNotDetectDependencyVulnWithScannerAnymore_Call) Return(_a0 error) *DependencyVulnService_UserDidNotDetectDependencyVulnWithScannerAnymore_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnService_UserDidNotDetectDependencyVulnWithScannerAnymore_Call) RunAndReturn(run func(*gorm.DB, []models.DependencyVuln, string, string) error) *DependencyVulnService_UserDidNotDetectDependencyVulnWithScannerAnymore_Call {
	_c.Call.Return(run)
	return _c
}

// UserFixedDependencyVulns provides a mock function with given fields: tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement
func (_m *DependencyVulnService) UserFixedDependencyVulns(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool) error {
	ret := _m.Called(tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)

	if len(ret) == 0 {
		panic("no return value specified for UserFixedDependencyVulns")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, []models.DependencyVuln, models.AssetVersion, models.Asset, bool) error); ok {
		r0 = rf(tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DependencyVulnService_UserFixedDependencyVulns_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UserFixedDependencyVulns'
type DependencyVulnService_UserFixedDependencyVulns_Call struct {
	*mock.Call
}

// UserFixedDependencyVulns is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - dependencyVulns []models.DependencyVuln
//   - assetVersion models.AssetVersion
//   - asset models.Asset
//   - doRiskManagement bool
func (_e *DependencyVulnService_Expecter) UserFixedDependencyVulns(tx interface{}, userID interface{}, dependencyVulns interface{}, assetVersion interface{}, asset interface{}, doRiskManagement interface{}) *DependencyVulnService_UserFixedDependencyVulns_Call {
	return &DependencyVulnService_UserFixedDependencyVulns_Call{Call: _e.mock.On("UserFixedDependencyVulns", tx, userID, dependencyVulns, assetVersion, asset, doRiskManagement)}
}

func (_c *DependencyVulnService_UserFixedDependencyVulns_Call) Run(run func(tx *gorm.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool)) *DependencyVulnService_UserFixedDependencyVulns_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].([]models.DependencyVuln), args[3].(models.AssetVersion), args[4].(models.Asset), args[5].(bool))
	})
	return _c
}

func (_c *DependencyVulnService_UserFixedDependencyVulns_Call) Return(_a0 error) *DependencyVulnService_UserFixedDependencyVulns_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *DependencyVulnService_UserFixedDependencyVulns_Call) RunAndReturn(run func(*gorm.DB, string, []models.DependencyVuln, models.AssetVersion, models.Asset, bool) error) *DependencyVulnService_UserFixedDependencyVulns_Call {
	_c.Call.Return(run)
	return _c
}

// NewDependencyVulnService creates a new instance of DependencyVulnService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewDependencyVulnService(t interface {
	mock.TestingT
	Cleanup(func())
}) *DependencyVulnService {
	mock := &DependencyVulnService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
