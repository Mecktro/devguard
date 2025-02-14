// Code generated by mockery v2.50.1. DO NOT EDIT.

package mocks

import (
	gorm "gorm.io/gorm"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// IntegrationsDependencyVulnEventRepository is an autogenerated mock type for the vulnEventRepository type
type IntegrationsDependencyVulnEventRepository struct {
	mock.Mock
}

type IntegrationsDependencyVulnEventRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *IntegrationsDependencyVulnEventRepository) EXPECT() *IntegrationsDependencyVulnEventRepository_Expecter {
	return &IntegrationsDependencyVulnEventRepository_Expecter{mock: &_m.Mock}
}

// Save provides a mock function with given fields: db, event
func (_m *IntegrationsDependencyVulnEventRepository) Save(db *gorm.DB, event *models.VulnEvent) error {
	ret := _m.Called(db, event)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.VulnEvent) error); ok {
		r0 = rf(db, event)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationsDependencyVulnEventRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type IntegrationsDependencyVulnEventRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - db *gorm.DB
//   - event *models.VulnEvent
func (_e *IntegrationsDependencyVulnEventRepository_Expecter) Save(db interface{}, event interface{}) *IntegrationsDependencyVulnEventRepository_Save_Call {
	return &IntegrationsDependencyVulnEventRepository_Save_Call{Call: _e.mock.On("Save", db, event)}
}

func (_c *IntegrationsDependencyVulnEventRepository_Save_Call) Run(run func(db *gorm.DB, event *models.VulnEvent)) *IntegrationsDependencyVulnEventRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.VulnEvent))
	})
	return _c
}

func (_c *IntegrationsDependencyVulnEventRepository_Save_Call) Return(_a0 error) *IntegrationsDependencyVulnEventRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationsDependencyVulnEventRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.VulnEvent) error) *IntegrationsDependencyVulnEventRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntegrationsDependencyVulnEventRepository creates a new instance of IntegrationsDependencyVulnEventRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntegrationsDependencyVulnEventRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntegrationsDependencyVulnEventRepository {
	mock := &IntegrationsDependencyVulnEventRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
