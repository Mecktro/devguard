// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"
)

// CoreComponentProjectRepository is an autogenerated mock type for the ComponentProjectRepository type
type CoreComponentProjectRepository struct {
	mock.Mock
}

type CoreComponentProjectRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreComponentProjectRepository) EXPECT() *CoreComponentProjectRepository_Expecter {
	return &CoreComponentProjectRepository_Expecter{mock: &_m.Mock}
}

// Activate provides a mock function with given fields: tx, id
func (_m *CoreComponentProjectRepository) Activate(tx *gorm.DB, id string) error {
	ret := _m.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Activate")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) error); ok {
		r0 = rf(tx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreComponentProjectRepository_Activate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Activate'
type CoreComponentProjectRepository_Activate_Call struct {
	*mock.Call
}

// Activate is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id string
func (_e *CoreComponentProjectRepository_Expecter) Activate(tx interface{}, id interface{}) *CoreComponentProjectRepository_Activate_Call {
	return &CoreComponentProjectRepository_Activate_Call{Call: _e.mock.On("Activate", tx, id)}
}

func (_c *CoreComponentProjectRepository_Activate_Call) Run(run func(tx *gorm.DB, id string)) *CoreComponentProjectRepository_Activate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *CoreComponentProjectRepository_Activate_Call) Return(_a0 error) *CoreComponentProjectRepository_Activate_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreComponentProjectRepository_Activate_Call) RunAndReturn(run func(*gorm.DB, string) error) *CoreComponentProjectRepository_Activate_Call {
	_c.Call.Return(run)
	return _c
}

// Begin provides a mock function with no fields
func (_m *CoreComponentProjectRepository) Begin() *gorm.DB {
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

// CoreComponentProjectRepository_Begin_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Begin'
type CoreComponentProjectRepository_Begin_Call struct {
	*mock.Call
}

// Begin is a helper method to define mock.On call
func (_e *CoreComponentProjectRepository_Expecter) Begin() *CoreComponentProjectRepository_Begin_Call {
	return &CoreComponentProjectRepository_Begin_Call{Call: _e.mock.On("Begin")}
}

func (_c *CoreComponentProjectRepository_Begin_Call) Run(run func()) *CoreComponentProjectRepository_Begin_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *CoreComponentProjectRepository_Begin_Call) Return(_a0 *gorm.DB) *CoreComponentProjectRepository_Begin_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreComponentProjectRepository_Begin_Call) RunAndReturn(run func() *gorm.DB) *CoreComponentProjectRepository_Begin_Call {
	_c.Call.Return(run)
	return _c
}

// Create provides a mock function with given fields: tx, t
func (_m *CoreComponentProjectRepository) Create(tx *gorm.DB, t *models.ComponentProject) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.ComponentProject) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreComponentProjectRepository_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type CoreComponentProjectRepository_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.ComponentProject
func (_e *CoreComponentProjectRepository_Expecter) Create(tx interface{}, t interface{}) *CoreComponentProjectRepository_Create_Call {
	return &CoreComponentProjectRepository_Create_Call{Call: _e.mock.On("Create", tx, t)}
}

func (_c *CoreComponentProjectRepository_Create_Call) Run(run func(tx *gorm.DB, t *models.ComponentProject)) *CoreComponentProjectRepository_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.ComponentProject))
	})
	return _c
}

func (_c *CoreComponentProjectRepository_Create_Call) Return(_a0 error) *CoreComponentProjectRepository_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreComponentProjectRepository_Create_Call) RunAndReturn(run func(*gorm.DB, *models.ComponentProject) error) *CoreComponentProjectRepository_Create_Call {
	_c.Call.Return(run)
	return _c
}

// CreateBatch provides a mock function with given fields: tx, ts
func (_m *CoreComponentProjectRepository) CreateBatch(tx *gorm.DB, ts []models.ComponentProject) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for CreateBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.ComponentProject) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreComponentProjectRepository_CreateBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateBatch'
type CoreComponentProjectRepository_CreateBatch_Call struct {
	*mock.Call
}

// CreateBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.ComponentProject
func (_e *CoreComponentProjectRepository_Expecter) CreateBatch(tx interface{}, ts interface{}) *CoreComponentProjectRepository_CreateBatch_Call {
	return &CoreComponentProjectRepository_CreateBatch_Call{Call: _e.mock.On("CreateBatch", tx, ts)}
}

func (_c *CoreComponentProjectRepository_CreateBatch_Call) Run(run func(tx *gorm.DB, ts []models.ComponentProject)) *CoreComponentProjectRepository_CreateBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.ComponentProject))
	})
	return _c
}

func (_c *CoreComponentProjectRepository_CreateBatch_Call) Return(_a0 error) *CoreComponentProjectRepository_CreateBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreComponentProjectRepository_CreateBatch_Call) RunAndReturn(run func(*gorm.DB, []models.ComponentProject) error) *CoreComponentProjectRepository_CreateBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: tx, id
func (_m *CoreComponentProjectRepository) Delete(tx *gorm.DB, id string) error {
	ret := _m.Called(tx, id)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) error); ok {
		r0 = rf(tx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreComponentProjectRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type CoreComponentProjectRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id string
func (_e *CoreComponentProjectRepository_Expecter) Delete(tx interface{}, id interface{}) *CoreComponentProjectRepository_Delete_Call {
	return &CoreComponentProjectRepository_Delete_Call{Call: _e.mock.On("Delete", tx, id)}
}

func (_c *CoreComponentProjectRepository_Delete_Call) Run(run func(tx *gorm.DB, id string)) *CoreComponentProjectRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *CoreComponentProjectRepository_Delete_Call) Return(_a0 error) *CoreComponentProjectRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreComponentProjectRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, string) error) *CoreComponentProjectRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// GetDB provides a mock function with given fields: tx
func (_m *CoreComponentProjectRepository) GetDB(tx *gorm.DB) *gorm.DB {
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

// CoreComponentProjectRepository_GetDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDB'
type CoreComponentProjectRepository_GetDB_Call struct {
	*mock.Call
}

// GetDB is a helper method to define mock.On call
//   - tx *gorm.DB
func (_e *CoreComponentProjectRepository_Expecter) GetDB(tx interface{}) *CoreComponentProjectRepository_GetDB_Call {
	return &CoreComponentProjectRepository_GetDB_Call{Call: _e.mock.On("GetDB", tx)}
}

func (_c *CoreComponentProjectRepository_GetDB_Call) Run(run func(tx *gorm.DB)) *CoreComponentProjectRepository_GetDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB))
	})
	return _c
}

func (_c *CoreComponentProjectRepository_GetDB_Call) Return(_a0 *gorm.DB) *CoreComponentProjectRepository_GetDB_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreComponentProjectRepository_GetDB_Call) RunAndReturn(run func(*gorm.DB) *gorm.DB) *CoreComponentProjectRepository_GetDB_Call {
	_c.Call.Return(run)
	return _c
}

// List provides a mock function with given fields: ids
func (_m *CoreComponentProjectRepository) List(ids []string) ([]models.ComponentProject, error) {
	ret := _m.Called(ids)

	if len(ret) == 0 {
		panic("no return value specified for List")
	}

	var r0 []models.ComponentProject
	var r1 error
	if rf, ok := ret.Get(0).(func([]string) ([]models.ComponentProject, error)); ok {
		return rf(ids)
	}
	if rf, ok := ret.Get(0).(func([]string) []models.ComponentProject); ok {
		r0 = rf(ids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.ComponentProject)
		}
	}

	if rf, ok := ret.Get(1).(func([]string) error); ok {
		r1 = rf(ids)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreComponentProjectRepository_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type CoreComponentProjectRepository_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
//   - ids []string
func (_e *CoreComponentProjectRepository_Expecter) List(ids interface{}) *CoreComponentProjectRepository_List_Call {
	return &CoreComponentProjectRepository_List_Call{Call: _e.mock.On("List", ids)}
}

func (_c *CoreComponentProjectRepository_List_Call) Run(run func(ids []string)) *CoreComponentProjectRepository_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]string))
	})
	return _c
}

func (_c *CoreComponentProjectRepository_List_Call) Return(_a0 []models.ComponentProject, _a1 error) *CoreComponentProjectRepository_List_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreComponentProjectRepository_List_Call) RunAndReturn(run func([]string) ([]models.ComponentProject, error)) *CoreComponentProjectRepository_List_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: id
func (_m *CoreComponentProjectRepository) Read(id string) (models.ComponentProject, error) {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.ComponentProject
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (models.ComponentProject, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(string) models.ComponentProject); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(models.ComponentProject)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreComponentProjectRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type CoreComponentProjectRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - id string
func (_e *CoreComponentProjectRepository_Expecter) Read(id interface{}) *CoreComponentProjectRepository_Read_Call {
	return &CoreComponentProjectRepository_Read_Call{Call: _e.mock.On("Read", id)}
}

func (_c *CoreComponentProjectRepository_Read_Call) Run(run func(id string)) *CoreComponentProjectRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *CoreComponentProjectRepository_Read_Call) Return(_a0 models.ComponentProject, _a1 error) *CoreComponentProjectRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreComponentProjectRepository_Read_Call) RunAndReturn(run func(string) (models.ComponentProject, error)) *CoreComponentProjectRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, t
func (_m *CoreComponentProjectRepository) Save(tx *gorm.DB, t *models.ComponentProject) error {
	ret := _m.Called(tx, t)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.ComponentProject) error); ok {
		r0 = rf(tx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreComponentProjectRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type CoreComponentProjectRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.ComponentProject
func (_e *CoreComponentProjectRepository_Expecter) Save(tx interface{}, t interface{}) *CoreComponentProjectRepository_Save_Call {
	return &CoreComponentProjectRepository_Save_Call{Call: _e.mock.On("Save", tx, t)}
}

func (_c *CoreComponentProjectRepository_Save_Call) Run(run func(tx *gorm.DB, t *models.ComponentProject)) *CoreComponentProjectRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.ComponentProject))
	})
	return _c
}

func (_c *CoreComponentProjectRepository_Save_Call) Return(_a0 error) *CoreComponentProjectRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreComponentProjectRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.ComponentProject) error) *CoreComponentProjectRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: tx, ts
func (_m *CoreComponentProjectRepository) SaveBatch(tx *gorm.DB, ts []models.ComponentProject) error {
	ret := _m.Called(tx, ts)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, []models.ComponentProject) error); ok {
		r0 = rf(tx, ts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreComponentProjectRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type CoreComponentProjectRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.ComponentProject
func (_e *CoreComponentProjectRepository_Expecter) SaveBatch(tx interface{}, ts interface{}) *CoreComponentProjectRepository_SaveBatch_Call {
	return &CoreComponentProjectRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, ts)}
}

func (_c *CoreComponentProjectRepository_SaveBatch_Call) Run(run func(tx *gorm.DB, ts []models.ComponentProject)) *CoreComponentProjectRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.ComponentProject))
	})
	return _c
}

func (_c *CoreComponentProjectRepository_SaveBatch_Call) Return(_a0 error) *CoreComponentProjectRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreComponentProjectRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.ComponentProject) error) *CoreComponentProjectRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: _a0
func (_m *CoreComponentProjectRepository) Transaction(_a0 func(*gorm.DB) error) error {
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

// CoreComponentProjectRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type CoreComponentProjectRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - _a0 func(*gorm.DB) error
func (_e *CoreComponentProjectRepository_Expecter) Transaction(_a0 interface{}) *CoreComponentProjectRepository_Transaction_Call {
	return &CoreComponentProjectRepository_Transaction_Call{Call: _e.mock.On("Transaction", _a0)}
}

func (_c *CoreComponentProjectRepository_Transaction_Call) Run(run func(_a0 func(*gorm.DB) error)) *CoreComponentProjectRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(*gorm.DB) error))
	})
	return _c
}

func (_c *CoreComponentProjectRepository_Transaction_Call) Return(_a0 error) *CoreComponentProjectRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreComponentProjectRepository_Transaction_Call) RunAndReturn(run func(func(*gorm.DB) error) error) *CoreComponentProjectRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreComponentProjectRepository creates a new instance of CoreComponentProjectRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreComponentProjectRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreComponentProjectRepository {
	mock := &CoreComponentProjectRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
