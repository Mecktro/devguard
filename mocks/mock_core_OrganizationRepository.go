// Code generated by mockery v2.53.0. DO NOT EDIT.

package mocks

import (
	common "github.com/l3montree-dev/devguard/internal/common"

	gorm "gorm.io/gorm"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"

	uuid "github.com/google/uuid"
)

// CoreOrganizationRepository is an autogenerated mock type for the OrganizationRepository type
type CoreOrganizationRepository struct {
	mock.Mock
}

type CoreOrganizationRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreOrganizationRepository) EXPECT() *CoreOrganizationRepository_Expecter {
	return &CoreOrganizationRepository_Expecter{mock: &_m.Mock}
}

// Activate provides a mock function with given fields: tx, id
func (_m *CoreOrganizationRepository) Activate(tx *gorm.DB, id uuid.UUID) error {
	ret := _m.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Activate")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, uuid.UUID) error); ok {
		r0 = rf(tx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreOrganizationRepository_Activate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Activate'
type CoreOrganizationRepository_Activate_Call struct {
	*mock.Call
}

// Activate is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id uuid.UUID
func (_e *CoreOrganizationRepository_Expecter) Activate(tx interface{}, id interface{}) *CoreOrganizationRepository_Activate_Call {
	return &CoreOrganizationRepository_Activate_Call{Call: _e.mock.On("Activate", tx, id)}
}

func (_c *CoreOrganizationRepository_Activate_Call) Run(run func(tx *gorm.DB, id uuid.UUID)) *CoreOrganizationRepository_Activate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *CoreOrganizationRepository_Activate_Call) Return(_a0 error) *CoreOrganizationRepository_Activate_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreOrganizationRepository_Activate_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) error) *CoreOrganizationRepository_Activate_Call {
	_c.Call.Return(run)
	return _c
}

// All provides a mock function with no fields
func (_m *CoreOrganizationRepository) All() ([]models.Org, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for All")
	}

	var r0 []models.Org
	var r1 error
	if rf, ok := ret.Get(0).(func() ([]models.Org, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() []models.Org); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Org)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreOrganizationRepository_All_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'All'
type CoreOrganizationRepository_All_Call struct {
	*mock.Call
}

// All is a helper method to define mock.On call
func (_e *CoreOrganizationRepository_Expecter) All() *CoreOrganizationRepository_All_Call {
	return &CoreOrganizationRepository_All_Call{Call: _e.mock.On("All")}
}

func (_c *CoreOrganizationRepository_All_Call) Run(run func()) *CoreOrganizationRepository_All_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *CoreOrganizationRepository_All_Call) Return(_a0 []models.Org, _a1 error) *CoreOrganizationRepository_All_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreOrganizationRepository_All_Call) RunAndReturn(run func() ([]models.Org, error)) *CoreOrganizationRepository_All_Call {
	_c.Call.Return(run)
	return _c
}

// Begin provides a mock function with no fields
func (_m *CoreOrganizationRepository) Begin() *gorm.DB {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Begin")
	}

	var r0 *gorm.DB
	if rf, ok := ret.Get(0).(func() *gorm.DB); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*gorm.DB)
		}
	}

	return r0
}

// CoreOrganizationRepository_Begin_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Begin'
type CoreOrganizationRepository_Begin_Call struct {
	*mock.Call
}

// Begin is a helper method to define mock.On call
func (_e *CoreOrganizationRepository_Expecter) Begin() *CoreOrganizationRepository_Begin_Call {
	return &CoreOrganizationRepository_Begin_Call{Call: _e.mock.On("Begin")}
}

func (_c *CoreOrganizationRepository_Begin_Call) Run(run func()) *CoreOrganizationRepository_Begin_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *CoreOrganizationRepository_Begin_Call) Return(_a0 *gorm.DB) *CoreOrganizationRepository_Begin_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreOrganizationRepository_Begin_Call) RunAndReturn(run func() *gorm.DB) *CoreOrganizationRepository_Begin_Call {
	_c.Call.Return(run)
	return _c
}

// ContentTree provides a mock function with given fields: orgID, projects
func (_m *CoreOrganizationRepository) ContentTree(orgID uuid.UUID, projects []string) []common.ContentTreeElement {
	ret := _m.Called(orgID, projects)

	if len(ret) == 0 {
		panic("no return value specified for ContentTree")
	}

	var r0 []common.ContentTreeElement
	if rf, ok := ret.Get(0).(func(uuid.UUID, []string) []common.ContentTreeElement); ok {
		r0 = rf(orgID, projects)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]common.ContentTreeElement)
		}
	}

	return r0
}

// CoreOrganizationRepository_ContentTree_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ContentTree'
type CoreOrganizationRepository_ContentTree_Call struct {
	*mock.Call
}

// ContentTree is a helper method to define mock.On call
//   - orgID uuid.UUID
//   - projects []string
func (_e *CoreOrganizationRepository_Expecter) ContentTree(orgID interface{}, projects interface{}) *CoreOrganizationRepository_ContentTree_Call {
	return &CoreOrganizationRepository_ContentTree_Call{Call: _e.mock.On("ContentTree", orgID, projects)}
}

func (_c *CoreOrganizationRepository_ContentTree_Call) Run(run func(orgID uuid.UUID, projects []string)) *CoreOrganizationRepository_ContentTree_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID), args[1].([]string))
	})
	return _c
}

func (_c *CoreOrganizationRepository_ContentTree_Call) Return(_a0 []common.ContentTreeElement) *CoreOrganizationRepository_ContentTree_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreOrganizationRepository_ContentTree_Call) RunAndReturn(run func(uuid.UUID, []string) []common.ContentTreeElement) *CoreOrganizationRepository_ContentTree_Call {
	_c.Call.Return(run)
	return _c
}

// Create provides a mock function with given fields: tx, t
func (_m *CoreOrganizationRepository) Create(tx *gorm.DB, t *models.Org) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Org) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreOrganizationRepository_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type CoreOrganizationRepository_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.Org
func (_e *CoreOrganizationRepository_Expecter) Create(tx interface{}, t interface{}) *CoreOrganizationRepository_Create_Call {
	return &CoreOrganizationRepository_Create_Call{Call: _e.mock.On("Create", tx, t)}
}

func (_c *CoreOrganizationRepository_Create_Call) Run(run func(tx *gorm.DB, t *models.Org)) *CoreOrganizationRepository_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Org))
	})
	return _c
}

func (_c *CoreOrganizationRepository_Create_Call) Return(_a0 error) *CoreOrganizationRepository_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreOrganizationRepository_Create_Call) RunAndReturn(run func(*gorm.DB, *models.Org) error) *CoreOrganizationRepository_Create_Call {
	_c.Call.Return(run)
	return _c
}

// CreateBatch provides a mock function with given fields: tx, ts
func (_m *CoreOrganizationRepository) CreateBatch(tx *gorm.DB, ts []models.Org) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for CreateBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.Org) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreOrganizationRepository_CreateBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateBatch'
type CoreOrganizationRepository_CreateBatch_Call struct {
	*mock.Call
}

// CreateBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.Org
func (_e *CoreOrganizationRepository_Expecter) CreateBatch(tx interface{}, ts interface{}) *CoreOrganizationRepository_CreateBatch_Call {
	return &CoreOrganizationRepository_CreateBatch_Call{Call: _e.mock.On("CreateBatch", tx, ts)}
}

func (_c *CoreOrganizationRepository_CreateBatch_Call) Run(run func(tx *gorm.DB, ts []models.Org)) *CoreOrganizationRepository_CreateBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.Org))
	})
	return _c
}

func (_c *CoreOrganizationRepository_CreateBatch_Call) Return(_a0 error) *CoreOrganizationRepository_CreateBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreOrganizationRepository_CreateBatch_Call) RunAndReturn(run func(*gorm.DB, []models.Org) error) *CoreOrganizationRepository_CreateBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: tx, id
func (_m *CoreOrganizationRepository) Delete(tx *gorm.DB, id uuid.UUID) error {
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

// CoreOrganizationRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type CoreOrganizationRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id uuid.UUID
func (_e *CoreOrganizationRepository_Expecter) Delete(tx interface{}, id interface{}) *CoreOrganizationRepository_Delete_Call {
	return &CoreOrganizationRepository_Delete_Call{Call: _e.mock.On("Delete", tx, id)}
}

func (_c *CoreOrganizationRepository_Delete_Call) Run(run func(tx *gorm.DB, id uuid.UUID)) *CoreOrganizationRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *CoreOrganizationRepository_Delete_Call) Return(_a0 error) *CoreOrganizationRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreOrganizationRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, uuid.UUID) error) *CoreOrganizationRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// GetDB provides a mock function with given fields: tx
func (_m *CoreOrganizationRepository) GetDB(tx *gorm.DB) *gorm.DB {
	ret := _m.Called(tx)

	if len(ret) == 0 {
		panic("no return value specified for GetDB")
	}

	var r0 *gorm.DB
	if rf, ok := ret.Get(0).(func(*gorm.DB) *gorm.DB); ok {
		r0 = rf(tx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*gorm.DB)
		}
	}

	return r0
}

// CoreOrganizationRepository_GetDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDB'
type CoreOrganizationRepository_GetDB_Call struct {
	*mock.Call
}

// GetDB is a helper method to define mock.On call
//   - tx *gorm.DB
func (_e *CoreOrganizationRepository_Expecter) GetDB(tx interface{}) *CoreOrganizationRepository_GetDB_Call {
	return &CoreOrganizationRepository_GetDB_Call{Call: _e.mock.On("GetDB", tx)}
}

func (_c *CoreOrganizationRepository_GetDB_Call) Run(run func(tx *gorm.DB)) *CoreOrganizationRepository_GetDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB))
	})
	return _c
}

func (_c *CoreOrganizationRepository_GetDB_Call) Return(_a0 *gorm.DB) *CoreOrganizationRepository_GetDB_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreOrganizationRepository_GetDB_Call) RunAndReturn(run func(*gorm.DB) *gorm.DB) *CoreOrganizationRepository_GetDB_Call {
	_c.Call.Return(run)
	return _c
}

// List provides a mock function with given fields: ids
func (_m *CoreOrganizationRepository) List(ids []uuid.UUID) ([]models.Org, error) {
	ret := _m.Called(ids)

	if len(ret) == 0 {
		panic("no return value specified for List")
	}

	var r0 []models.Org
	var r1 error
	if rf, ok := ret.Get(0).(func([]uuid.UUID) ([]models.Org, error)); ok {
		return rf(ids)
	}
	if rf, ok := ret.Get(0).(func([]uuid.UUID) []models.Org); ok {
		r0 = rf(ids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Org)
		}
	}

	if rf, ok := ret.Get(1).(func([]uuid.UUID) error); ok {
		r1 = rf(ids)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreOrganizationRepository_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type CoreOrganizationRepository_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
//   - ids []uuid.UUID
func (_e *CoreOrganizationRepository_Expecter) List(ids interface{}) *CoreOrganizationRepository_List_Call {
	return &CoreOrganizationRepository_List_Call{Call: _e.mock.On("List", ids)}
}

func (_c *CoreOrganizationRepository_List_Call) Run(run func(ids []uuid.UUID)) *CoreOrganizationRepository_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]uuid.UUID))
	})
	return _c
}

func (_c *CoreOrganizationRepository_List_Call) Return(_a0 []models.Org, _a1 error) *CoreOrganizationRepository_List_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreOrganizationRepository_List_Call) RunAndReturn(run func([]uuid.UUID) ([]models.Org, error)) *CoreOrganizationRepository_List_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: id
func (_m *CoreOrganizationRepository) Read(id uuid.UUID) (models.Org, error) {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.Org
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) (models.Org, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) models.Org); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(models.Org)
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreOrganizationRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type CoreOrganizationRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - id uuid.UUID
func (_e *CoreOrganizationRepository_Expecter) Read(id interface{}) *CoreOrganizationRepository_Read_Call {
	return &CoreOrganizationRepository_Read_Call{Call: _e.mock.On("Read", id)}
}

func (_c *CoreOrganizationRepository_Read_Call) Run(run func(id uuid.UUID)) *CoreOrganizationRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *CoreOrganizationRepository_Read_Call) Return(_a0 models.Org, _a1 error) *CoreOrganizationRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreOrganizationRepository_Read_Call) RunAndReturn(run func(uuid.UUID) (models.Org, error)) *CoreOrganizationRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// ReadBySlug provides a mock function with given fields: slug
func (_m *CoreOrganizationRepository) ReadBySlug(slug string) (models.Org, error) {
	ret := _m.Called(slug)

	if len(ret) == 0 {
		panic("no return value specified for ReadBySlug")
	}

	var r0 models.Org
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (models.Org, error)); ok {
		return rf(slug)
	}
	if rf, ok := ret.Get(0).(func(string) models.Org); ok {
		r0 = rf(slug)
	} else {
		r0 = ret.Get(0).(models.Org)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(slug)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreOrganizationRepository_ReadBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReadBySlug'
type CoreOrganizationRepository_ReadBySlug_Call struct {
	*mock.Call
}

// ReadBySlug is a helper method to define mock.On call
//   - slug string
func (_e *CoreOrganizationRepository_Expecter) ReadBySlug(slug interface{}) *CoreOrganizationRepository_ReadBySlug_Call {
	return &CoreOrganizationRepository_ReadBySlug_Call{Call: _e.mock.On("ReadBySlug", slug)}
}

func (_c *CoreOrganizationRepository_ReadBySlug_Call) Run(run func(slug string)) *CoreOrganizationRepository_ReadBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *CoreOrganizationRepository_ReadBySlug_Call) Return(_a0 models.Org, _a1 error) *CoreOrganizationRepository_ReadBySlug_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreOrganizationRepository_ReadBySlug_Call) RunAndReturn(run func(string) (models.Org, error)) *CoreOrganizationRepository_ReadBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, t
func (_m *CoreOrganizationRepository) Save(tx *gorm.DB, t *models.Org) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Org) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreOrganizationRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type CoreOrganizationRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.Org
func (_e *CoreOrganizationRepository_Expecter) Save(tx interface{}, t interface{}) *CoreOrganizationRepository_Save_Call {
	return &CoreOrganizationRepository_Save_Call{Call: _e.mock.On("Save", tx, t)}
}

func (_c *CoreOrganizationRepository_Save_Call) Run(run func(tx *gorm.DB, t *models.Org)) *CoreOrganizationRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Org))
	})
	return _c
}

func (_c *CoreOrganizationRepository_Save_Call) Return(_a0 error) *CoreOrganizationRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreOrganizationRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.Org) error) *CoreOrganizationRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: tx, ts
func (_m *CoreOrganizationRepository) SaveBatch(tx *gorm.DB, ts []models.Org) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.Org) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreOrganizationRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type CoreOrganizationRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.Org
func (_e *CoreOrganizationRepository_Expecter) SaveBatch(tx interface{}, ts interface{}) *CoreOrganizationRepository_SaveBatch_Call {
	return &CoreOrganizationRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, ts)}
}

func (_c *CoreOrganizationRepository_SaveBatch_Call) Run(run func(tx *gorm.DB, ts []models.Org)) *CoreOrganizationRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.Org))
	})
	return _c
}

func (_c *CoreOrganizationRepository_SaveBatch_Call) Return(_a0 error) *CoreOrganizationRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreOrganizationRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.Org) error) *CoreOrganizationRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: _a0
func (_m *CoreOrganizationRepository) Transaction(_a0 func(*gorm.DB) error) error {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for Transaction")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(func(*gorm.DB) error) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreOrganizationRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type CoreOrganizationRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - _a0 func(*gorm.DB) error
func (_e *CoreOrganizationRepository_Expecter) Transaction(_a0 interface{}) *CoreOrganizationRepository_Transaction_Call {
	return &CoreOrganizationRepository_Transaction_Call{Call: _e.mock.On("Transaction", _a0)}
}

func (_c *CoreOrganizationRepository_Transaction_Call) Run(run func(_a0 func(*gorm.DB) error)) *CoreOrganizationRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(*gorm.DB) error))
	})
	return _c
}

func (_c *CoreOrganizationRepository_Transaction_Call) Return(_a0 error) *CoreOrganizationRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreOrganizationRepository_Transaction_Call) RunAndReturn(run func(func(*gorm.DB) error) error) *CoreOrganizationRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// Update provides a mock function with given fields: tx, organization
func (_m *CoreOrganizationRepository) Update(tx *gorm.DB, organization *models.Org) error {
	ret := _m.Called(tx, organization)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Org) error); ok {
		r0 = rf(tx, organization)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreOrganizationRepository_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Update'
type CoreOrganizationRepository_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
//   - tx *gorm.DB
//   - organization *models.Org
func (_e *CoreOrganizationRepository_Expecter) Update(tx interface{}, organization interface{}) *CoreOrganizationRepository_Update_Call {
	return &CoreOrganizationRepository_Update_Call{Call: _e.mock.On("Update", tx, organization)}
}

func (_c *CoreOrganizationRepository_Update_Call) Run(run func(tx *gorm.DB, organization *models.Org)) *CoreOrganizationRepository_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Org))
	})
	return _c
}

func (_c *CoreOrganizationRepository_Update_Call) Return(_a0 error) *CoreOrganizationRepository_Update_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreOrganizationRepository_Update_Call) RunAndReturn(run func(*gorm.DB, *models.Org) error) *CoreOrganizationRepository_Update_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreOrganizationRepository creates a new instance of CoreOrganizationRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreOrganizationRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreOrganizationRepository {
	mock := &CoreOrganizationRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
