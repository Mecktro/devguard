// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	gorm "gorm.io/gorm"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"

	uuid "github.com/google/uuid"
)

// IntegrationsGitlabIntegrationRepository is an autogenerated mock type for the gitlabIntegrationRepository type
type IntegrationsGitlabIntegrationRepository struct {
	mock.Mock
}

type IntegrationsGitlabIntegrationRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *IntegrationsGitlabIntegrationRepository) EXPECT() *IntegrationsGitlabIntegrationRepository_Expecter {
	return &IntegrationsGitlabIntegrationRepository_Expecter{mock: &_m.Mock}
}

// Delete provides a mock function with given fields: tx, id
func (_m *IntegrationsGitlabIntegrationRepository) Delete(tx *gorm.DB, id uuid.UUID) error {
	ret := _m.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) error); ok {
		r0 = rf(tx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationsGitlabIntegrationRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type IntegrationsGitlabIntegrationRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id uuid.UUID
func (_e *IntegrationsGitlabIntegrationRepository_Expecter) Delete(tx interface{}, id interface{}) *IntegrationsGitlabIntegrationRepository_Delete_Call {
	return &IntegrationsGitlabIntegrationRepository_Delete_Call{Call: _e.mock.On("Delete", tx, id)}
}

func (_c *IntegrationsGitlabIntegrationRepository_Delete_Call) Run(run func(tx *gorm.DB, id uuid.UUID)) *IntegrationsGitlabIntegrationRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *IntegrationsGitlabIntegrationRepository_Delete_Call) Return(_a0 error) *IntegrationsGitlabIntegrationRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationsGitlabIntegrationRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) error) *IntegrationsGitlabIntegrationRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// FindByOrganizationId provides a mock function with given fields: orgID
func (_m *IntegrationsGitlabIntegrationRepository) FindByOrganizationId(orgID uuid.UUID) ([]models.GitLabIntegration, error) {
	ret := _m.Called(orgID)

	if len(ret) == 0 {
		panic("no return value specified for FindByOrganizationId")
	}

	var r0 []models.GitLabIntegration
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) ([]models.GitLabIntegration, error)); ok {
		return rf(orgID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) []models.GitLabIntegration); ok {
		r0 = rf(orgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.GitLabIntegration)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(orgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntegrationsGitlabIntegrationRepository_FindByOrganizationId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByOrganizationId'
type IntegrationsGitlabIntegrationRepository_FindByOrganizationId_Call struct {
	*mock.Call
}

// FindByOrganizationId is a helper method to define mock.On call
//   - orgID uuid.UUID
func (_e *IntegrationsGitlabIntegrationRepository_Expecter) FindByOrganizationId(orgID interface{}) *IntegrationsGitlabIntegrationRepository_FindByOrganizationId_Call {
	return &IntegrationsGitlabIntegrationRepository_FindByOrganizationId_Call{Call: _e.mock.On("FindByOrganizationId", orgID)}
}

func (_c *IntegrationsGitlabIntegrationRepository_FindByOrganizationId_Call) Run(run func(orgID uuid.UUID)) *IntegrationsGitlabIntegrationRepository_FindByOrganizationId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *IntegrationsGitlabIntegrationRepository_FindByOrganizationId_Call) Return(_a0 []models.GitLabIntegration, _a1 error) *IntegrationsGitlabIntegrationRepository_FindByOrganizationId_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntegrationsGitlabIntegrationRepository_FindByOrganizationId_Call) RunAndReturn(run func(uuid.UUID) ([]models.GitLabIntegration, error)) *IntegrationsGitlabIntegrationRepository_FindByOrganizationId_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: id
func (_m *IntegrationsGitlabIntegrationRepository) Read(id uuid.UUID) (models.GitLabIntegration, error) {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.GitLabIntegration
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) (models.GitLabIntegration, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) models.GitLabIntegration); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(models.GitLabIntegration)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntegrationsGitlabIntegrationRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type IntegrationsGitlabIntegrationRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - id uuid.UUID
func (_e *IntegrationsGitlabIntegrationRepository_Expecter) Read(id interface{}) *IntegrationsGitlabIntegrationRepository_Read_Call {
	return &IntegrationsGitlabIntegrationRepository_Read_Call{Call: _e.mock.On("Read", id)}
}

func (_c *IntegrationsGitlabIntegrationRepository_Read_Call) Run(run func(id uuid.UUID)) *IntegrationsGitlabIntegrationRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *IntegrationsGitlabIntegrationRepository_Read_Call) Return(_a0 models.GitLabIntegration, _a1 error) *IntegrationsGitlabIntegrationRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntegrationsGitlabIntegrationRepository_Read_Call) RunAndReturn(run func(uuid.UUID) (models.GitLabIntegration, error)) *IntegrationsGitlabIntegrationRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, model
func (_m *IntegrationsGitlabIntegrationRepository) Save(tx *gorm.DB, model *models.GitLabIntegration) error {
	ret := _m.Called(tx, model)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.GitLabIntegration) error); ok {
		r0 = rf(tx, model)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationsGitlabIntegrationRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type IntegrationsGitlabIntegrationRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - model *models.GitLabIntegration
func (_e *IntegrationsGitlabIntegrationRepository_Expecter) Save(tx interface{}, model interface{}) *IntegrationsGitlabIntegrationRepository_Save_Call {
	return &IntegrationsGitlabIntegrationRepository_Save_Call{Call: _e.mock.On("Save", tx, model)}
}

func (_c *IntegrationsGitlabIntegrationRepository_Save_Call) Run(run func(tx *gorm.DB, model *models.GitLabIntegration)) *IntegrationsGitlabIntegrationRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.GitLabIntegration))
	})
	return _c
}

func (_c *IntegrationsGitlabIntegrationRepository_Save_Call) Return(_a0 error) *IntegrationsGitlabIntegrationRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationsGitlabIntegrationRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.GitLabIntegration) error) *IntegrationsGitlabIntegrationRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntegrationsGitlabIntegrationRepository creates a new instance of IntegrationsGitlabIntegrationRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntegrationsGitlabIntegrationRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntegrationsGitlabIntegrationRepository {
	mock := &IntegrationsGitlabIntegrationRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
