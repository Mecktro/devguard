// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	echo "github.com/labstack/echo/v4"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// DependencyVulnProjectService is an autogenerated mock type for the projectService type
type DependencyVulnProjectService struct {
	mock.Mock
}

type DependencyVulnProjectService_Expecter struct {
	mock *mock.Mock
}

func (_m *DependencyVulnProjectService) EXPECT() *DependencyVulnProjectService_Expecter {
	return &DependencyVulnProjectService_Expecter{mock: &_m.Mock}
}

// ListAllowedProjects provides a mock function with given fields: c
func (_m *DependencyVulnProjectService) ListAllowedProjects(c echo.Context) ([]models.Project, error) {
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

// DependencyVulnProjectService_ListAllowedProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListAllowedProjects'
type DependencyVulnProjectService_ListAllowedProjects_Call struct {
	*mock.Call
}

// ListAllowedProjects is a helper method to define mock.On call
//   - c echo.Context
func (_e *DependencyVulnProjectService_Expecter) ListAllowedProjects(c interface{}) *DependencyVulnProjectService_ListAllowedProjects_Call {
	return &DependencyVulnProjectService_ListAllowedProjects_Call{Call: _e.mock.On("ListAllowedProjects", c)}
}

func (_c *DependencyVulnProjectService_ListAllowedProjects_Call) Run(run func(c echo.Context)) *DependencyVulnProjectService_ListAllowedProjects_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *DependencyVulnProjectService_ListAllowedProjects_Call) Return(_a0 []models.Project, _a1 error) *DependencyVulnProjectService_ListAllowedProjects_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *DependencyVulnProjectService_ListAllowedProjects_Call) RunAndReturn(run func(echo.Context) ([]models.Project, error)) *DependencyVulnProjectService_ListAllowedProjects_Call {
	_c.Call.Return(run)
	return _c
}

// NewDependencyVulnProjectService creates a new instance of DependencyVulnProjectService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewDependencyVulnProjectService(t interface {
	mock.TestingT
	Cleanup(func())
}) *DependencyVulnProjectService {
	mock := &DependencyVulnProjectService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
