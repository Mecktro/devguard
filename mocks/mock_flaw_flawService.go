// Code generated by mockery v2.43.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"
)

// FlawFlawService is an autogenerated mock type for the flawService type
type FlawFlawService struct {
	mock.Mock
}

type FlawFlawService_Expecter struct {
	mock *mock.Mock
}

func (_m *FlawFlawService) EXPECT() *FlawFlawService_Expecter {
	return &FlawFlawService_Expecter{mock: &_m.Mock}
}

// UpdateFlawState provides a mock function with given fields: tx, userID, _a2, statusType, justification
func (_m *FlawFlawService) UpdateFlawState(tx *gorm.DB, userID string, _a2 *models.Flaw, statusType string, justification *string) error {
	ret := _m.Called(tx, userID, _a2, statusType, justification)

	if len(ret) == 0 {
		panic("no return value specified for UpdateFlawState")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string, *models.Flaw, string, *string) error); ok {
		r0 = rf(tx, userID, _a2, statusType, justification)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FlawFlawService_UpdateFlawState_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UpdateFlawState'
type FlawFlawService_UpdateFlawState_Call struct {
	*mock.Call
}

// UpdateFlawState is a helper method to define mock.On call
//   - tx *gorm.DB
//   - userID string
//   - _a2 *models.Flaw
//   - statusType string
//   - justification *string
func (_e *FlawFlawService_Expecter) UpdateFlawState(tx interface{}, userID interface{}, _a2 interface{}, statusType interface{}, justification interface{}) *FlawFlawService_UpdateFlawState_Call {
	return &FlawFlawService_UpdateFlawState_Call{Call: _e.mock.On("UpdateFlawState", tx, userID, _a2, statusType, justification)}
}

func (_c *FlawFlawService_UpdateFlawState_Call) Run(run func(tx *gorm.DB, userID string, _a2 *models.Flaw, statusType string, justification *string)) *FlawFlawService_UpdateFlawState_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string), args[2].(*models.Flaw), args[3].(string), args[4].(*string))
	})
	return _c
}

func (_c *FlawFlawService_UpdateFlawState_Call) Return(_a0 error) *FlawFlawService_UpdateFlawState_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *FlawFlawService_UpdateFlawState_Call) RunAndReturn(run func(*gorm.DB, string, *models.Flaw, string, *string) error) *FlawFlawService_UpdateFlawState_Call {
	_c.Call.Return(run)
	return _c
}

// NewFlawFlawService creates a new instance of FlawFlawService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFlawFlawService(t interface {
	mock.TestingT
	Cleanup(func())
}) *FlawFlawService {
	mock := &FlawFlawService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
