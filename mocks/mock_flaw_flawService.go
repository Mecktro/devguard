// Code generated by mockery v2.50.1. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"
)

// VulnVulnService is an autogenerated mock type for the vulnService type
type VulnVulnService struct {
	mock.Mock
}

type VulnVulnService_Expecter struct {
	mock *mock.Mock
}

func (_m *VulnVulnService) EXPECT() *VulnVulnService_Expecter {
	return &VulnVulnService_Expecter{mock: &_m.Mock}
}

// UpdateVulnState provides a mock function with given fields: tx, userID, _a2, statusType, justification
func (_m *VulnVulnService) UpdateVulnState(tx *gorm.DB, userID string, _a2 *models.DependencyVulnerability, statusType string, justification string) (models.VulnEvent, error) {
	ret := _m.Called(tx, userID, _a2, statusType, justification)

	if len(ret) == 0 {
		panic("no return value specified for UpdateVulnState")
	}

	var r0 models.VulnEvent
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, *models.DependencyVulnerability, string, string) (models.VulnEvent, error)); ok {
		return rf(tx, userID, _a2, statusType, justification)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, *models.DependencyVulnerability, string, string) models.VulnEvent); ok {
		r0 = rf(tx, userID, _a2, statusType, justification)
	} else {
		r0 = ret.Get(0).(models.VulnEvent)
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, string, *models.DependencyVulnerability, string, string) error); ok {
		r1 = rf(tx, userID, _a2, statusType, justification)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// VulnVulnService_UpdateVulnState_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateVulnState'
type VulnVulnService_UpdateVulnState_Call struct {
	*mock.Call
}

// UpdateVulnState is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - _a2 *models.Vuln
//   - statusType string
//   - justification string
func (_e *VulnVulnService_Expecter) UpdateVulnState(tx interface{}, userID interface{}, _a2 interface{}, statusType interface{}, justification interface{}) *VulnVulnService_UpdateVulnState_Call {
	return &VulnVulnService_UpdateVulnState_Call{Call: _e.mock.On("UpdateVulnState", tx, userID, _a2, statusType, justification)}
}

func (_c *VulnVulnService_UpdateVulnState_Call) Run(run func(tx *gorm.DB, userID string, _a2 *models.DependencyVulnerability, statusType string, justification string)) *VulnVulnService_UpdateVulnState_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].(*models.DependencyVulnerability), args[3].(string), args[4].(string))
	})
	return _c
}

func (_c *VulnVulnService_UpdateVulnState_Call) Return(_a0 models.VulnEvent, _a1 error) *VulnVulnService_UpdateVulnState_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *VulnVulnService_UpdateVulnState_Call) RunAndReturn(run func(*gorm.DB, string, *models.DependencyVulnerability, string, string) (models.VulnEvent, error)) *VulnVulnService_UpdateVulnState_Call {
	_c.Call.Return(run)
	return _c
}

// NewVulnVulnService creates a new instance of VulnVulnService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewVulnVulnService(t interface {
	mock.TestingT
	Cleanup(func())
}) *VulnVulnService {
	mock := &VulnVulnService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
