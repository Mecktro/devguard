// Code generated by mockery v2.53.2. DO NOT EDIT.

package mocks

import (
	echo "github.com/labstack/echo/v4"
	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"

	uuid "github.com/google/uuid"
)

// ProjectService is an autogenerated mock type for the ProjectService type
type ProjectService struct {
	mock.Mock
}

type ProjectService_Expecter struct {
	mock *mock.Mock
}

func (_m *ProjectService) EXPECT() *ProjectService_Expecter {
	return &ProjectService_Expecter{mock: &_m.Mock}
}

// GetDirectChildProjects provides a mock function with given fields: projectID
func (_m *ProjectService) GetDirectChildProjects(projectID uuid.UUID) ([]models.Project, error) {
	ret := _m.Called(projectID)

	if len(ret) == 0 {
		panic("no return value specified for GetDirectChildProjects")
	}

	var r0 []models.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) ([]models.Project, error)); ok {
		return rf(projectID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) []models.Project); ok {
		r0 = rf(projectID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(projectID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProjectService_GetDirectChildProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDirectChildProjects'
type ProjectService_GetDirectChildProjects_Call struct {
	*mock.Call
}

// GetDirectChildProjects is a helper method to define mock.On call
//   - projectID uuid.UUID
func (_e *ProjectService_Expecter) GetDirectChildProjects(projectID interface{}) *ProjectService_GetDirectChildProjects_Call {
	return &ProjectService_GetDirectChildProjects_Call{Call: _e.mock.On("GetDirectChildProjects", projectID)}
}

func (_c *ProjectService_GetDirectChildProjects_Call) Run(run func(projectID uuid.UUID)) *ProjectService_GetDirectChildProjects_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *ProjectService_GetDirectChildProjects_Call) Return(_a0 []models.Project, _a1 error) *ProjectService_GetDirectChildProjects_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProjectService_GetDirectChildProjects_Call) RunAndReturn(run func(uuid.UUID) ([]models.Project, error)) *ProjectService_GetDirectChildProjects_Call {
	_c.Call.Return(run)
	return _c
}

// ListAllowedProjects provides a mock function with given fields: ctx
func (_m *ProjectService) ListAllowedProjects(ctx echo.Context) ([]models.Project, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for ListAllowedProjects")
	}

	var r0 []models.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(echo.Context) ([]models.Project, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(echo.Context) []models.Project); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(echo.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProjectService_ListAllowedProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListAllowedProjects'
type ProjectService_ListAllowedProjects_Call struct {
	*mock.Call
}

// ListAllowedProjects is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *ProjectService_Expecter) ListAllowedProjects(ctx interface{}) *ProjectService_ListAllowedProjects_Call {
	return &ProjectService_ListAllowedProjects_Call{Call: _e.mock.On("ListAllowedProjects", ctx)}
}

func (_c *ProjectService_ListAllowedProjects_Call) Run(run func(ctx echo.Context)) *ProjectService_ListAllowedProjects_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *ProjectService_ListAllowedProjects_Call) Return(_a0 []models.Project, _a1 error) *ProjectService_ListAllowedProjects_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProjectService_ListAllowedProjects_Call) RunAndReturn(run func(echo.Context) ([]models.Project, error)) *ProjectService_ListAllowedProjects_Call {
	_c.Call.Return(run)
	return _c
}

// ListProjectsByOrganizationID provides a mock function with given fields: organizationID
func (_m *ProjectService) ListProjectsByOrganizationID(organizationID uuid.UUID) ([]models.Project, error) {
	ret := _m.Called(organizationID)

	if len(ret) == 0 {
		panic("no return value specified for ListProjectsByOrganizationID")
	}

	var r0 []models.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) ([]models.Project, error)); ok {
		return rf(organizationID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) []models.Project); ok {
		r0 = rf(organizationID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(organizationID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProjectService_ListProjectsByOrganizationID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListProjectsByOrganizationID'
type ProjectService_ListProjectsByOrganizationID_Call struct {
	*mock.Call
}

// ListProjectsByOrganizationID is a helper method to define mock.On call
//   - organizationID uuid.UUID
func (_e *ProjectService_Expecter) ListProjectsByOrganizationID(organizationID interface{}) *ProjectService_ListProjectsByOrganizationID_Call {
	return &ProjectService_ListProjectsByOrganizationID_Call{Call: _e.mock.On("ListProjectsByOrganizationID", organizationID)}
}

func (_c *ProjectService_ListProjectsByOrganizationID_Call) Run(run func(organizationID uuid.UUID)) *ProjectService_ListProjectsByOrganizationID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *ProjectService_ListProjectsByOrganizationID_Call) Return(_a0 []models.Project, _a1 error) *ProjectService_ListProjectsByOrganizationID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProjectService_ListProjectsByOrganizationID_Call) RunAndReturn(run func(uuid.UUID) ([]models.Project, error)) *ProjectService_ListProjectsByOrganizationID_Call {
	_c.Call.Return(run)
	return _c
}

// RecursivelyGetChildProjects provides a mock function with given fields: projectID
func (_m *ProjectService) RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error) {
	ret := _m.Called(projectID)

	if len(ret) == 0 {
		panic("no return value specified for RecursivelyGetChildProjects")
	}

	var r0 []models.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) ([]models.Project, error)); ok {
		return rf(projectID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) []models.Project); ok {
		r0 = rf(projectID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(projectID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProjectService_RecursivelyGetChildProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RecursivelyGetChildProjects'
type ProjectService_RecursivelyGetChildProjects_Call struct {
	*mock.Call
}

// RecursivelyGetChildProjects is a helper method to define mock.On call
//   - projectID uuid.UUID
func (_e *ProjectService_Expecter) RecursivelyGetChildProjects(projectID interface{}) *ProjectService_RecursivelyGetChildProjects_Call {
	return &ProjectService_RecursivelyGetChildProjects_Call{Call: _e.mock.On("RecursivelyGetChildProjects", projectID)}
}

func (_c *ProjectService_RecursivelyGetChildProjects_Call) Run(run func(projectID uuid.UUID)) *ProjectService_RecursivelyGetChildProjects_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *ProjectService_RecursivelyGetChildProjects_Call) Return(_a0 []models.Project, _a1 error) *ProjectService_RecursivelyGetChildProjects_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProjectService_RecursivelyGetChildProjects_Call) RunAndReturn(run func(uuid.UUID) ([]models.Project, error)) *ProjectService_RecursivelyGetChildProjects_Call {
	_c.Call.Return(run)
	return _c
}

// NewProjectService creates a new instance of ProjectService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewProjectService(t interface {
	mock.TestingT
	Cleanup(func())
}) *ProjectService {
	mock := &ProjectService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
