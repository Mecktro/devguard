// Code generated by mockery v2.50.1. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"

	uuid "github.com/google/uuid"
)

// ProjectProjectRepository is an autogenerated mock type for the projectRepository type
type ProjectProjectRepository struct {
	mock.Mock
}

type ProjectProjectRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *ProjectProjectRepository) EXPECT() *ProjectProjectRepository_Expecter {
	return &ProjectProjectRepository_Expecter{mock: &_m.Mock}
}

// Activate provides a mock function with given fields: tx, projectID
func (_m *ProjectProjectRepository) Activate(tx *gorm.DB, projectID uuid.UUID) error {
	ret := _m.Called(tx, projectID)

	if len(ret) == 0 {
		panic("no return value specified for Activate")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) error); ok {
		r0 = rf(tx, projectID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ProjectProjectRepository_Activate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Activate'
type ProjectProjectRepository_Activate_Call struct {
	*mock.Call
}

// Activate is a helper method to define mock.On call
//   - tx *gorm.DB
//   - projectID uuid.UUID
func (_e *ProjectProjectRepository_Expecter) Activate(tx interface{}, projectID interface{}) *ProjectProjectRepository_Activate_Call {
	return &ProjectProjectRepository_Activate_Call{Call: _e.mock.On("Activate", tx, projectID)}
}

func (_c *ProjectProjectRepository_Activate_Call) Run(run func(tx *gorm.DB, projectID uuid.UUID)) *ProjectProjectRepository_Activate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *ProjectProjectRepository_Activate_Call) Return(_a0 error) *ProjectProjectRepository_Activate_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ProjectProjectRepository_Activate_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) error) *ProjectProjectRepository_Activate_Call {
	_c.Call.Return(run)
	return _c
}

// Create provides a mock function with given fields: tx, _a1
func (_m *ProjectProjectRepository) Create(tx *gorm.DB, _a1 *models.Project) error {
	ret := _m.Called(tx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Project) error); ok {
		r0 = rf(tx, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ProjectProjectRepository_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type ProjectProjectRepository_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - tx *gorm.DB
//   - _a1 *models.Project
func (_e *ProjectProjectRepository_Expecter) Create(tx interface{}, _a1 interface{}) *ProjectProjectRepository_Create_Call {
	return &ProjectProjectRepository_Create_Call{Call: _e.mock.On("Create", tx, _a1)}
}

func (_c *ProjectProjectRepository_Create_Call) Run(run func(tx *gorm.DB, _a1 *models.Project)) *ProjectProjectRepository_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Project))
	})
	return _c
}

func (_c *ProjectProjectRepository_Create_Call) Return(_a0 error) *ProjectProjectRepository_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ProjectProjectRepository_Create_Call) RunAndReturn(run func(*gorm.DB, *models.Project) error) *ProjectProjectRepository_Create_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: tx, projectID
func (_m *ProjectProjectRepository) Delete(tx *gorm.DB, projectID uuid.UUID) error {
	ret := _m.Called(tx, projectID)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) error); ok {
		r0 = rf(tx, projectID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ProjectProjectRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type ProjectProjectRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - projectID uuid.UUID
func (_e *ProjectProjectRepository_Expecter) Delete(tx interface{}, projectID interface{}) *ProjectProjectRepository_Delete_Call {
	return &ProjectProjectRepository_Delete_Call{Call: _e.mock.On("Delete", tx, projectID)}
}

func (_c *ProjectProjectRepository_Delete_Call) Run(run func(tx *gorm.DB, projectID uuid.UUID)) *ProjectProjectRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *ProjectProjectRepository_Delete_Call) Return(_a0 error) *ProjectProjectRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ProjectProjectRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) error) *ProjectProjectRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// GetDirectChildProjects provides a mock function with given fields: projectID
func (_m *ProjectProjectRepository) GetDirectChildProjects(projectID uuid.UUID) ([]models.Project, error) {
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

// ProjectProjectRepository_GetDirectChildProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDirectChildProjects'
type ProjectProjectRepository_GetDirectChildProjects_Call struct {
	*mock.Call
}

// GetDirectChildProjects is a helper method to define mock.On call
//   - projectID uuid.UUID
func (_e *ProjectProjectRepository_Expecter) GetDirectChildProjects(projectID interface{}) *ProjectProjectRepository_GetDirectChildProjects_Call {
	return &ProjectProjectRepository_GetDirectChildProjects_Call{Call: _e.mock.On("GetDirectChildProjects", projectID)}
}

func (_c *ProjectProjectRepository_GetDirectChildProjects_Call) Run(run func(projectID uuid.UUID)) *ProjectProjectRepository_GetDirectChildProjects_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *ProjectProjectRepository_GetDirectChildProjects_Call) Return(_a0 []models.Project, _a1 error) *ProjectProjectRepository_GetDirectChildProjects_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProjectProjectRepository_GetDirectChildProjects_Call) RunAndReturn(run func(uuid.UUID) ([]models.Project, error)) *ProjectProjectRepository_GetDirectChildProjects_Call {
	_c.Call.Return(run)
	return _c
}

// List provides a mock function with given fields: projectIds, parentId, orgId
func (_m *ProjectProjectRepository) List(projectIds []uuid.UUID, parentId *uuid.UUID, orgId uuid.UUID) ([]models.Project, error) {
	ret := _m.Called(projectIds, parentId, orgId)

	if len(ret) == 0 {
		panic("no return value specified for List")
	}

	var r0 []models.Project
	var r1 error
	if rf, ok := ret.Get(0).(func([]uuid.UUID, *uuid.UUID, uuid.UUID) ([]models.Project, error)); ok {
		return rf(projectIds, parentId, orgId)
	}
	if rf, ok := ret.Get(0).(func([]uuid.UUID, *uuid.UUID, uuid.UUID) []models.Project); ok {
		r0 = rf(projectIds, parentId, orgId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Project)
		}
	}

	if rf, ok := ret.Get(1).(func([]uuid.UUID, *uuid.UUID, uuid.UUID) error); ok {
		r1 = rf(projectIds, parentId, orgId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProjectProjectRepository_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type ProjectProjectRepository_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
//   - projectIds []uuid.UUID
//   - parentId *uuid.UUID
//   - orgId uuid.UUID
func (_e *ProjectProjectRepository_Expecter) List(projectIds interface{}, parentId interface{}, orgId interface{}) *ProjectProjectRepository_List_Call {
	return &ProjectProjectRepository_List_Call{Call: _e.mock.On("List", projectIds, parentId, orgId)}
}

func (_c *ProjectProjectRepository_List_Call) Run(run func(projectIds []uuid.UUID, parentId *uuid.UUID, orgId uuid.UUID)) *ProjectProjectRepository_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]uuid.UUID), args[1].(*uuid.UUID), args[2].(uuid.UUID))
	})
	return _c
}

func (_c *ProjectProjectRepository_List_Call) Return(_a0 []models.Project, _a1 error) *ProjectProjectRepository_List_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProjectProjectRepository_List_Call) RunAndReturn(run func([]uuid.UUID, *uuid.UUID, uuid.UUID) ([]models.Project, error)) *ProjectProjectRepository_List_Call {
	_c.Call.Return(run)
	return _c
}

// ReadBySlug provides a mock function with given fields: organizationID, slug
func (_m *ProjectProjectRepository) ReadBySlug(organizationID uuid.UUID, slug string) (models.Project, error) {
	ret := _m.Called(organizationID, slug)

	if len(ret) == 0 {
		panic("no return value specified for ReadBySlug")
	}

	var r0 models.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, string) (models.Project, error)); ok {
		return rf(organizationID, slug)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, string) models.Project); ok {
		r0 = rf(organizationID, slug)
	} else {
		r0 = ret.Get(0).(models.Project)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, string) error); ok {
		r1 = rf(organizationID, slug)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProjectProjectRepository_ReadBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReadBySlug'
type ProjectProjectRepository_ReadBySlug_Call struct {
	*mock.Call
}

// ReadBySlug is a helper method to define mock.On call
//   - organizationID uuid.UUID
//   - slug string
func (_e *ProjectProjectRepository_Expecter) ReadBySlug(organizationID interface{}, slug interface{}) *ProjectProjectRepository_ReadBySlug_Call {
	return &ProjectProjectRepository_ReadBySlug_Call{Call: _e.mock.On("ReadBySlug", organizationID, slug)}
}

func (_c *ProjectProjectRepository_ReadBySlug_Call) Run(run func(organizationID uuid.UUID, slug string)) *ProjectProjectRepository_ReadBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(string))
	})
	return _c
}

func (_c *ProjectProjectRepository_ReadBySlug_Call) Return(_a0 models.Project, _a1 error) *ProjectProjectRepository_ReadBySlug_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProjectProjectRepository_ReadBySlug_Call) RunAndReturn(run func(uuid.UUID, string) (models.Project, error)) *ProjectProjectRepository_ReadBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// ReadBySlugUnscoped provides a mock function with given fields: organizationId, slug
func (_m *ProjectProjectRepository) ReadBySlugUnscoped(organizationId uuid.UUID, slug string) (models.Project, error) {
	ret := _m.Called(organizationId, slug)

	if len(ret) == 0 {
		panic("no return value specified for ReadBySlugUnscoped")
	}

	var r0 models.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID, string) (models.Project, error)); ok {
		return rf(organizationId, slug)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID, string) models.Project); ok {
		r0 = rf(organizationId, slug)
	} else {
		r0 = ret.Get(0).(models.Project)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID, string) error); ok {
		r1 = rf(organizationId, slug)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProjectProjectRepository_ReadBySlugUnscoped_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReadBySlugUnscoped'
type ProjectProjectRepository_ReadBySlugUnscoped_Call struct {
	*mock.Call
}

// ReadBySlugUnscoped is a helper method to define mock.On call
//   - organizationId uuid.UUID
//   - slug string
func (_e *ProjectProjectRepository_Expecter) ReadBySlugUnscoped(organizationId interface{}, slug interface{}) *ProjectProjectRepository_ReadBySlugUnscoped_Call {
	return &ProjectProjectRepository_ReadBySlugUnscoped_Call{Call: _e.mock.On("ReadBySlugUnscoped", organizationId, slug)}
}

func (_c *ProjectProjectRepository_ReadBySlugUnscoped_Call) Run(run func(organizationId uuid.UUID, slug string)) *ProjectProjectRepository_ReadBySlugUnscoped_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].(string))
	})
	return _c
}

func (_c *ProjectProjectRepository_ReadBySlugUnscoped_Call) Return(_a0 models.Project, _a1 error) *ProjectProjectRepository_ReadBySlugUnscoped_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProjectProjectRepository_ReadBySlugUnscoped_Call) RunAndReturn(run func(uuid.UUID, string) (models.Project, error)) *ProjectProjectRepository_ReadBySlugUnscoped_Call {
	_c.Call.Return(run)
	return _c
}

// RecursivelyGetChildProjects provides a mock function with given fields: projectID
func (_m *ProjectProjectRepository) RecursivelyGetChildProjects(projectID uuid.UUID) ([]models.Project, error) {
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

// ProjectProjectRepository_RecursivelyGetChildProjects_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RecursivelyGetChildProjects'
type ProjectProjectRepository_RecursivelyGetChildProjects_Call struct {
	*mock.Call
}

// RecursivelyGetChildProjects is a helper method to define mock.On call
//   - projectID uuid.UUID
func (_e *ProjectProjectRepository_Expecter) RecursivelyGetChildProjects(projectID interface{}) *ProjectProjectRepository_RecursivelyGetChildProjects_Call {
	return &ProjectProjectRepository_RecursivelyGetChildProjects_Call{Call: _e.mock.On("RecursivelyGetChildProjects", projectID)}
}

func (_c *ProjectProjectRepository_RecursivelyGetChildProjects_Call) Run(run func(projectID uuid.UUID)) *ProjectProjectRepository_RecursivelyGetChildProjects_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *ProjectProjectRepository_RecursivelyGetChildProjects_Call) Return(_a0 []models.Project, _a1 error) *ProjectProjectRepository_RecursivelyGetChildProjects_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ProjectProjectRepository_RecursivelyGetChildProjects_Call) RunAndReturn(run func(uuid.UUID) ([]models.Project, error)) *ProjectProjectRepository_RecursivelyGetChildProjects_Call {
	_c.Call.Return(run)
	return _c
}

// Update provides a mock function with given fields: tx, _a1
func (_m *ProjectProjectRepository) Update(tx *gorm.DB, _a1 *models.Project) error {
	ret := _m.Called(tx, _a1)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Project) error); ok {
		r0 = rf(tx, _a1)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ProjectProjectRepository_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Update'
type ProjectProjectRepository_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
//   - tx *gorm.DB
//   - _a1 *models.Project
func (_e *ProjectProjectRepository_Expecter) Update(tx interface{}, _a1 interface{}) *ProjectProjectRepository_Update_Call {
	return &ProjectProjectRepository_Update_Call{Call: _e.mock.On("Update", tx, _a1)}
}

func (_c *ProjectProjectRepository_Update_Call) Run(run func(tx *gorm.DB, _a1 *models.Project)) *ProjectProjectRepository_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Project))
	})
	return _c
}

func (_c *ProjectProjectRepository_Update_Call) Return(_a0 error) *ProjectProjectRepository_Update_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ProjectProjectRepository_Update_Call) RunAndReturn(run func(*gorm.DB, *models.Project) error) *ProjectProjectRepository_Update_Call {
	_c.Call.Return(run)
	return _c
}

// NewProjectProjectRepository creates a new instance of ProjectProjectRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewProjectProjectRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *ProjectProjectRepository {
	mock := &ProjectProjectRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
