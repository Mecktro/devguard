// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
	gorm "gorm.io/gorm"
)

// ComponentProjectRepository is an autogenerated mock type for the ComponentProjectRepository type
type ComponentProjectRepository struct {
	mock.Mock
}

type ComponentProjectRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *ComponentProjectRepository) EXPECT() *ComponentProjectRepository_Expecter {
	return &ComponentProjectRepository_Expecter{mock: &_m.Mock}
}

// Activate provides a mock function with given fields: tx, id
func (_m *ComponentProjectRepository) Activate(tx *gorm.DB, id string) error {
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

// ComponentProjectRepository_Activate_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Activate'
type ComponentProjectRepository_Activate_Call struct {
	*mock.Call
}

// Activate is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id string
func (_e *ComponentProjectRepository_Expecter) Activate(tx interface{}, id interface{}) *ComponentProjectRepository_Activate_Call {
	return &ComponentProjectRepository_Activate_Call{Call: _e.mock.On("Activate", tx, id)}
}

func (_c *ComponentProjectRepository_Activate_Call) Run(run func(tx *gorm.DB, id string)) *ComponentProjectRepository_Activate_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *ComponentProjectRepository_Activate_Call) Return(_a0 error) *ComponentProjectRepository_Activate_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ComponentProjectRepository_Activate_Call) RunAndReturn(run func(*gorm.DB, string) error) *ComponentProjectRepository_Activate_Call {
	_c.Call.Return(run)
	return _c
}

// All provides a mock function with no fields
func (_m *ComponentProjectRepository) All() ([]models.ComponentProject, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for All")
	}

	var r0 []models.ComponentProject
	var r1 error
	if rf, ok := ret.Get(0).(func() ([]models.ComponentProject, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() []models.ComponentProject); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.ComponentProject)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ComponentProjectRepository_All_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'All'
type ComponentProjectRepository_All_Call struct {
	*mock.Call
}

// All is a helper method to define mock.On call
func (_e *ComponentProjectRepository_Expecter) All() *ComponentProjectRepository_All_Call {
	return &ComponentProjectRepository_All_Call{Call: _e.mock.On("All")}
}

func (_c *ComponentProjectRepository_All_Call) Run(run func()) *ComponentProjectRepository_All_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ComponentProjectRepository_All_Call) Return(_a0 []models.ComponentProject, _a1 error) *ComponentProjectRepository_All_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ComponentProjectRepository_All_Call) RunAndReturn(run func() ([]models.ComponentProject, error)) *ComponentProjectRepository_All_Call {
	_c.Call.Return(run)
	return _c
}

// Begin provides a mock function with no fields
func (_m *ComponentProjectRepository) Begin() *gorm.DB {
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

// ComponentProjectRepository_Begin_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Begin'
type ComponentProjectRepository_Begin_Call struct {
	*mock.Call
}

// Begin is a helper method to define mock.On call
func (_e *ComponentProjectRepository_Expecter) Begin() *ComponentProjectRepository_Begin_Call {
	return &ComponentProjectRepository_Begin_Call{Call: _e.mock.On("Begin")}
}

func (_c *ComponentProjectRepository_Begin_Call) Run(run func()) *ComponentProjectRepository_Begin_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *ComponentProjectRepository_Begin_Call) Return(_a0 *gorm.DB) *ComponentProjectRepository_Begin_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ComponentProjectRepository_Begin_Call) RunAndReturn(run func() *gorm.DB) *ComponentProjectRepository_Begin_Call {
	_c.Call.Return(run)
	return _c
}

// Create provides a mock function with given fields: tx, t
func (_m *ComponentProjectRepository) Create(tx *gorm.DB, t *models.ComponentProject) error {
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

// ComponentProjectRepository_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type ComponentProjectRepository_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.ComponentProject
func (_e *ComponentProjectRepository_Expecter) Create(tx interface{}, t interface{}) *ComponentProjectRepository_Create_Call {
	return &ComponentProjectRepository_Create_Call{Call: _e.mock.On("Create", tx, t)}
}

func (_c *ComponentProjectRepository_Create_Call) Run(run func(tx *gorm.DB, t *models.ComponentProject)) *ComponentProjectRepository_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.ComponentProject))
	})
	return _c
}

func (_c *ComponentProjectRepository_Create_Call) Return(_a0 error) *ComponentProjectRepository_Create_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ComponentProjectRepository_Create_Call) RunAndReturn(run func(*gorm.DB, *models.ComponentProject) error) *ComponentProjectRepository_Create_Call {
	_c.Call.Return(run)
	return _c
}

// CreateBatch provides a mock function with given fields: tx, ts
func (_m *ComponentProjectRepository) CreateBatch(tx *gorm.DB, ts []models.ComponentProject) error {
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

// ComponentProjectRepository_CreateBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateBatch'
type ComponentProjectRepository_CreateBatch_Call struct {
	*mock.Call
}

// CreateBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.ComponentProject
func (_e *ComponentProjectRepository_Expecter) CreateBatch(tx interface{}, ts interface{}) *ComponentProjectRepository_CreateBatch_Call {
	return &ComponentProjectRepository_CreateBatch_Call{Call: _e.mock.On("CreateBatch", tx, ts)}
}

func (_c *ComponentProjectRepository_CreateBatch_Call) Run(run func(tx *gorm.DB, ts []models.ComponentProject)) *ComponentProjectRepository_CreateBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.ComponentProject))
	})
	return _c
}

func (_c *ComponentProjectRepository_CreateBatch_Call) Return(_a0 error) *ComponentProjectRepository_CreateBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ComponentProjectRepository_CreateBatch_Call) RunAndReturn(run func(*gorm.DB, []models.ComponentProject) error) *ComponentProjectRepository_CreateBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: tx, id
func (_m *ComponentProjectRepository) Delete(tx *gorm.DB, id string) error {
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

// ComponentProjectRepository_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type ComponentProjectRepository_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - tx *gorm.DB
//   - id string
func (_e *ComponentProjectRepository_Expecter) Delete(tx interface{}, id interface{}) *ComponentProjectRepository_Delete_Call {
	return &ComponentProjectRepository_Delete_Call{Call: _e.mock.On("Delete", tx, id)}
}

func (_c *ComponentProjectRepository_Delete_Call) Run(run func(tx *gorm.DB, id string)) *ComponentProjectRepository_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *ComponentProjectRepository_Delete_Call) Return(_a0 error) *ComponentProjectRepository_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ComponentProjectRepository_Delete_Call) RunAndReturn(run func(*gorm.DB, string) error) *ComponentProjectRepository_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// GetDB provides a mock function with given fields: tx
func (_m *ComponentProjectRepository) GetDB(tx *gorm.DB) *gorm.DB {
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

// ComponentProjectRepository_GetDB_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDB'
type ComponentProjectRepository_GetDB_Call struct {
	*mock.Call
}

// GetDB is a helper method to define mock.On call
//   - tx *gorm.DB
func (_e *ComponentProjectRepository_Expecter) GetDB(tx interface{}) *ComponentProjectRepository_GetDB_Call {
	return &ComponentProjectRepository_GetDB_Call{Call: _e.mock.On("GetDB", tx)}
}

func (_c *ComponentProjectRepository_GetDB_Call) Run(run func(tx *gorm.DB)) *ComponentProjectRepository_GetDB_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB))
	})
	return _c
}

func (_c *ComponentProjectRepository_GetDB_Call) Return(_a0 *gorm.DB) *ComponentProjectRepository_GetDB_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ComponentProjectRepository_GetDB_Call) RunAndReturn(run func(*gorm.DB) *gorm.DB) *ComponentProjectRepository_GetDB_Call {
	_c.Call.Return(run)
	return _c
}

// List provides a mock function with given fields: ids
func (_m *ComponentProjectRepository) List(ids []string) ([]models.ComponentProject, error) {
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

// ComponentProjectRepository_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type ComponentProjectRepository_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
//   - ids []string
func (_e *ComponentProjectRepository_Expecter) List(ids interface{}) *ComponentProjectRepository_List_Call {
	return &ComponentProjectRepository_List_Call{Call: _e.mock.On("List", ids)}
}

func (_c *ComponentProjectRepository_List_Call) Run(run func(ids []string)) *ComponentProjectRepository_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]string))
	})
	return _c
}

func (_c *ComponentProjectRepository_List_Call) Return(_a0 []models.ComponentProject, _a1 error) *ComponentProjectRepository_List_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ComponentProjectRepository_List_Call) RunAndReturn(run func([]string) ([]models.ComponentProject, error)) *ComponentProjectRepository_List_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: id
func (_m *ComponentProjectRepository) Read(id string) (models.ComponentProject, error) {
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

// ComponentProjectRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type ComponentProjectRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - id string
func (_e *ComponentProjectRepository_Expecter) Read(id interface{}) *ComponentProjectRepository_Read_Call {
	return &ComponentProjectRepository_Read_Call{Call: _e.mock.On("Read", id)}
}

func (_c *ComponentProjectRepository_Read_Call) Run(run func(id string)) *ComponentProjectRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *ComponentProjectRepository_Read_Call) Return(_a0 models.ComponentProject, _a1 error) *ComponentProjectRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *ComponentProjectRepository_Read_Call) RunAndReturn(run func(string) (models.ComponentProject, error)) *ComponentProjectRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: tx, t
func (_m *ComponentProjectRepository) Save(tx *gorm.DB, t *models.ComponentProject) error {
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

// ComponentProjectRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type ComponentProjectRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - tx *gorm.DB
//   - t *models.ComponentProject
func (_e *ComponentProjectRepository_Expecter) Save(tx interface{}, t interface{}) *ComponentProjectRepository_Save_Call {
	return &ComponentProjectRepository_Save_Call{Call: _e.mock.On("Save", tx, t)}
}

func (_c *ComponentProjectRepository_Save_Call) Run(run func(tx *gorm.DB, t *models.ComponentProject)) *ComponentProjectRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.ComponentProject))
	})
	return _c
}

func (_c *ComponentProjectRepository_Save_Call) Return(_a0 error) *ComponentProjectRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ComponentProjectRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.ComponentProject) error) *ComponentProjectRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// SaveBatch provides a mock function with given fields: tx, ts
func (_m *ComponentProjectRepository) SaveBatch(tx *gorm.DB, ts []models.ComponentProject) error {
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

// ComponentProjectRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type ComponentProjectRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ts []models.ComponentProject
func (_e *ComponentProjectRepository_Expecter) SaveBatch(tx interface{}, ts interface{}) *ComponentProjectRepository_SaveBatch_Call {
	return &ComponentProjectRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, ts)}
}

func (_c *ComponentProjectRepository_SaveBatch_Call) Run(run func(tx *gorm.DB, ts []models.ComponentProject)) *ComponentProjectRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].([]models.ComponentProject))
	})
	return _c
}

func (_c *ComponentProjectRepository_SaveBatch_Call) Return(_a0 error) *ComponentProjectRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ComponentProjectRepository_SaveBatch_Call) RunAndReturn(run func(*gorm.DB, []models.ComponentProject) error) *ComponentProjectRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: _a0
func (_m *ComponentProjectRepository) Transaction(_a0 func(*gorm.DB) error) error {
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

// ComponentProjectRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type ComponentProjectRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - _a0 func(*gorm.DB) error
func (_e *ComponentProjectRepository_Expecter) Transaction(_a0 interface{}) *ComponentProjectRepository_Transaction_Call {
	return &ComponentProjectRepository_Transaction_Call{Call: _e.mock.On("Transaction", _a0)}
}

func (_c *ComponentProjectRepository_Transaction_Call) Run(run func(_a0 func(*gorm.DB) error)) *ComponentProjectRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(*gorm.DB) error))
	})
	return _c
}

func (_c *ComponentProjectRepository_Transaction_Call) Return(_a0 error) *ComponentProjectRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *ComponentProjectRepository_Transaction_Call) RunAndReturn(run func(func(*gorm.DB) error) error) *ComponentProjectRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewComponentProjectRepository creates a new instance of ComponentProjectRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewComponentProjectRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *ComponentProjectRepository {
	mock := &ComponentProjectRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
