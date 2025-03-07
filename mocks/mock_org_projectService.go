// Code generated by mockery v2.53.0. DO NOT EDIT.

package mocks

import (
	echo "github.com/labstack/echo/v4"
	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"

	uuid "github.com/google/uuid"
)

// OrgProjectService is an autogenerated mock type for the projectService type
type OrgProjectService struct {
	mock.Mock
}

type OrgProjectService_Expecter struct {
	mock *mock.Mock
}

func (_m *OrgProjectService) EXPECT() *OrgProjectService_Expecter {
	return &OrgProjectService_Expecter{mock: &_m.Mock}
}

// ListAllowedProjects provides a mock function with given fields: c
func (_m *OrgProjectService) ListAllowedProjects(c echo.Context) ([]models.Project, error) {
	ret := _m.Called(c)

	if len(ret) == 0 {
		panic("no return value specified for ListAllowedProjects")
	}

	var r0 []models.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(echo.Context) ([]models.Project, error)); ok {
		return rf(c)
	}
	if rf, ok := ret.Get(0).(func(echo.Context) []models.Project); ok {
		r0 = rf(c)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(echo.Context) error); ok {
		r1 = rf(c)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// OrgProjectService_ListAllowedProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListAllowedProjects'
type OrgProjectService_ListAllowedProjects_Call struct {
	*mock.Call
}

// ListAllowedProjects is a helper method to define mock.On call
//   - c echo.Context
func (_e *OrgProjectService_Expecter) ListAllowedProjects(c interface{}) *OrgProjectService_ListAllowedProjects_Call {
	return &OrgProjectService_ListAllowedProjects_Call{Call: _e.mock.On("ListAllowedProjects", c)}
}

func (_c *OrgProjectService_ListAllowedProjects_Call) Run(run func(c echo.Context)) *OrgProjectService_ListAllowedProjects_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *OrgProjectService_ListAllowedProjects_Call) Return(_a0 []models.Project, _a1 error) *OrgProjectService_ListAllowedProjects_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *OrgProjectService_ListAllowedProjects_Call) RunAndReturn(run func(echo.Context) ([]models.Project, error)) *OrgProjectService_ListAllowedProjects_Call {
	_c.Call.Return(run)
	return _c
}

// ListProjectsByOrganizationID provides a mock function with given fields: organizationID
func (_m *OrgProjectService) ListProjectsByOrganizationID(organizationID uuid.UUID) ([]models.Project, error) {
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

// OrgProjectService_ListProjectsByOrganizationID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListProjectsByOrganizationID'
type OrgProjectService_ListProjectsByOrganizationID_Call struct {
	*mock.Call
}

// ListProjectsByOrganizationID is a helper method to define mock.On call
//   - organizationID uuid.UUID
func (_e *OrgProjectService_Expecter) ListProjectsByOrganizationID(organizationID interface{}) *OrgProjectService_ListProjectsByOrganizationID_Call {
	return &OrgProjectService_ListProjectsByOrganizationID_Call{Call: _e.mock.On("ListProjectsByOrganizationID", organizationID)}
}

func (_c *OrgProjectService_ListProjectsByOrganizationID_Call) Run(run func(organizationID uuid.UUID)) *OrgProjectService_ListProjectsByOrganizationID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *OrgProjectService_ListProjectsByOrganizationID_Call) Return(_a0 []models.Project, _a1 error) *OrgProjectService_ListProjectsByOrganizationID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *OrgProjectService_ListProjectsByOrganizationID_Call) RunAndReturn(run func(uuid.UUID) ([]models.Project, error)) *OrgProjectService_ListProjectsByOrganizationID_Call {
	_c.Call.Return(run)
	return _c
}

// NewOrgProjectService creates a new instance of OrgProjectService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewOrgProjectService(t interface {
	mock.TestingT
	Cleanup(func())
}) *OrgProjectService {
	mock := &OrgProjectService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
