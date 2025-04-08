// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	uuid "github.com/google/uuid"
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// ComponentService is an autogenerated mock type for the ComponentService type
type ComponentService struct {
	mock.Mock
}

type ComponentService_Expecter struct {
	mock *mock.Mock
}

func (_m *ComponentService) EXPECT() *ComponentService_Expecter {
	return &ComponentService_Expecter{mock: &_m.Mock}
}

// GetAndSaveLicenseInformation provides a mock function with given fields: assetVersionName, assetID, scanner
func (_m *ComponentService) GetAndSaveLicenseInformation(assetVersionName string, assetID uuid.UUID, scanner string) ([]models.Component, error) {
	ret := _m.Called(assetVersionName, assetID, scanner)

	if len(ret) == 0 {
		panic("no return value specified for GetAndSaveLicenseInformation")
	}

	var r0 []models.Component
	var r1 error
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string) ([]models.Component, error)); ok {
		return rf(assetVersionName, assetID, scanner)
	}
	if rf, ok := ret.Get(0).(func(string, uuid.UUID, string) []models.Component); ok {
		r0 = rf(assetVersionName, assetID, scanner)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Component)
		}
	}

	if rf, ok := ret.Get(1).(func(string, uuid.UUID, string) error); ok {
		r1 = rf(assetVersionName, assetID, scanner)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ComponentService_GetAndSaveLicenseInformation_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetAndSaveLicenseInformation'
type ComponentService_GetAndSaveLicenseInformation_Call struct {
	*mock.Call
}

// GetAndSaveLicenseInformation is a helper method to define mock.On call
//   - assetVersionName string
//   - assetID uuid.UUID
//   - scanner string
func (_e *ComponentService_Expecter) GetAndSaveLicenseInformation(assetVersionName interface{}, assetID interface{}, scanner interface{}) *ComponentService_GetAndSaveLicenseInformation_Call {
	return &ComponentService_GetAndSaveLicenseInformation_Call{Call: _e.mock.On("GetAndSaveLicenseInformation", assetVersionName, assetID, scanner)}
}

func (_c *ComponentService_GetAndSaveLicenseInformation_Call) Run(run func(assetVersionName string, assetID uuid.UUID, scanner string)) *ComponentService_GetAndSaveLicenseInformation_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(uuid.UUID), args[2].(string))
	})
	return _c
}

func (_c *ComponentService_GetAndSaveLicenseInformation_Call) Return(_a0 []models.Component, _a1 error) *ComponentService_GetAndSaveLicenseInformation_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ComponentService_GetAndSaveLicenseInformation_Call) RunAndReturn(run func(string, uuid.UUID, string) ([]models.Component, error)) *ComponentService_GetAndSaveLicenseInformation_Call {
	_c.Call.Return(run)
	return _c
}

// GetLicense provides a mock function with given fields: component
func (_m *ComponentService) GetLicense(component models.Component) (models.Component, error) {
	ret := _m.Called(component)

	if len(ret) == 0 {
		panic("no return value specified for GetLicense")
	}

	var r0 models.Component
	var r1 error
	if rf, ok := ret.Get(0).(func(models.Component) (models.Component, error)); ok {
		return rf(component)
	}
	if rf, ok := ret.Get(0).(func(models.Component) models.Component); ok {
		r0 = rf(component)
	} else {
		r0 = ret.Get(0).(models.Component)
	}

	if rf, ok := ret.Get(1).(func(models.Component) error); ok {
		r1 = rf(component)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ComponentService_GetLicense_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetLicense'
type ComponentService_GetLicense_Call struct {
	*mock.Call
}

// GetLicense is a helper method to define mock.On call
//   - component models.Component
func (_e *ComponentService_Expecter) GetLicense(component interface{}) *ComponentService_GetLicense_Call {
	return &ComponentService_GetLicense_Call{Call: _e.mock.On("GetLicense", component)}
}

func (_c *ComponentService_GetLicense_Call) Run(run func(component models.Component)) *ComponentService_GetLicense_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Component))
	})
	return _c
}

func (_c *ComponentService_GetLicense_Call) Return(_a0 models.Component, _a1 error) *ComponentService_GetLicense_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ComponentService_GetLicense_Call) RunAndReturn(run func(models.Component) (models.Component, error)) *ComponentService_GetLicense_Call {
	_c.Call.Return(run)
	return _c
}

// RefreshComponentProjectInformation provides a mock function with given fields: project
func (_m *ComponentService) RefreshComponentProjectInformation(project models.ComponentProject) {
	_m.Called(project)
}

// ComponentService_RefreshComponentProjectInformation_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RefreshComponentProjectInformation'
type ComponentService_RefreshComponentProjectInformation_Call struct {
	*mock.Call
}

// RefreshComponentProjectInformation is a helper method to define mock.On call
//   - project models.ComponentProject
func (_e *ComponentService_Expecter) RefreshComponentProjectInformation(project interface{}) *ComponentService_RefreshComponentProjectInformation_Call {
	return &ComponentService_RefreshComponentProjectInformation_Call{Call: _e.mock.On("RefreshComponentProjectInformation", project)}
}

func (_c *ComponentService_RefreshComponentProjectInformation_Call) Run(run func(project models.ComponentProject)) *ComponentService_RefreshComponentProjectInformation_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.ComponentProject))
	})
	return _c
}

func (_c *ComponentService_RefreshComponentProjectInformation_Call) Return() *ComponentService_RefreshComponentProjectInformation_Call {
	_c.Call.Return()
	return _c
}

func (_c *ComponentService_RefreshComponentProjectInformation_Call) RunAndReturn(run func(models.ComponentProject)) *ComponentService_RefreshComponentProjectInformation_Call {
	_c.Run(run)
	return _c
}

// NewComponentService creates a new instance of ComponentService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewComponentService(t interface {
	mock.TestingT
	Cleanup(func())
}) *ComponentService {
	mock := &ComponentService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
