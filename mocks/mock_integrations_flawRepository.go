// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	gorm "gorm.io/gorm"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// IntegrationsFlawRepository is an autogenerated mock type for the flawRepository type
type IntegrationsFlawRepository struct {
	mock.Mock
}

type IntegrationsFlawRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *IntegrationsFlawRepository) EXPECT() *IntegrationsFlawRepository_Expecter {
	return &IntegrationsFlawRepository_Expecter{mock: &_m.Mock}
}

// FindByTicketID provides a mock function with given fields: tx, ticketID
func (_m *IntegrationsFlawRepository) FindByTicketID(tx *gorm.DB, ticketID string) (models.Flaw, error) {
	ret := _m.Called(tx, ticketID)

	if len(ret) == 0 {
		panic("no return value specified for FindByTicketID")
	}

	var r0 models.Flaw
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) (models.Flaw, error)); ok {
		return rf(tx, ticketID)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) models.Flaw); ok {
		r0 = rf(tx, ticketID)
	} else {
		r0 = ret.Get(0).(models.Flaw)
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, string) error); ok {
		r1 = rf(tx, ticketID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntegrationsFlawRepository_FindByTicketID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindByTicketID'
type IntegrationsFlawRepository_FindByTicketID_Call struct {
	*mock.Call
}

// FindByTicketID is a helper method to define mock.On call
//   - tx *gorm.DB
//   - ticketID string
func (_e *IntegrationsFlawRepository_Expecter) FindByTicketID(tx interface{}, ticketID interface{}) *IntegrationsFlawRepository_FindByTicketID_Call {
	return &IntegrationsFlawRepository_FindByTicketID_Call{Call: _e.mock.On("FindByTicketID", tx, ticketID)}
}

func (_c *IntegrationsFlawRepository_FindByTicketID_Call) Run(run func(tx *gorm.DB, ticketID string)) *IntegrationsFlawRepository_FindByTicketID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *IntegrationsFlawRepository_FindByTicketID_Call) Return(_a0 models.Flaw, _a1 error) *IntegrationsFlawRepository_FindByTicketID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntegrationsFlawRepository_FindByTicketID_Call) RunAndReturn(run func(*gorm.DB, string) (models.Flaw, error)) *IntegrationsFlawRepository_FindByTicketID_Call {
	_c.Call.Return(run)
	return _c
}

// GetOrgFromFlawID provides a mock function with given fields: tx, flawID
func (_m *IntegrationsFlawRepository) GetOrgFromFlawID(tx *gorm.DB, flawID string) (models.Org, error) {
	ret := _m.Called(tx, flawID)

	if len(ret) == 0 {
		panic("no return value specified for GetOrgFromFlawID")
	}

	var r0 models.Org
	var r1 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) (models.Org, error)); ok {
		return rf(tx, flawID)
	}
	if rf, ok := ret.Get(0).(func(*gorm.DB, string) models.Org); ok {
		r0 = rf(tx, flawID)
	} else {
		r0 = ret.Get(0).(models.Org)
	}

	if rf, ok := ret.Get(1).(func(*gorm.DB, string) error); ok {
		r1 = rf(tx, flawID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntegrationsFlawRepository_GetOrgFromFlawID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOrgFromFlawID'
type IntegrationsFlawRepository_GetOrgFromFlawID_Call struct {
	*mock.Call
}

// GetOrgFromFlawID is a helper method to define mock.On call
//   - tx *gorm.DB
//   - flawID string
func (_e *IntegrationsFlawRepository_Expecter) GetOrgFromFlawID(tx interface{}, flawID interface{}) *IntegrationsFlawRepository_GetOrgFromFlawID_Call {
	return &IntegrationsFlawRepository_GetOrgFromFlawID_Call{Call: _e.mock.On("GetOrgFromFlawID", tx, flawID)}
}

func (_c *IntegrationsFlawRepository_GetOrgFromFlawID_Call) Run(run func(tx *gorm.DB, flawID string)) *IntegrationsFlawRepository_GetOrgFromFlawID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(string))
	})
	return _c
}

func (_c *IntegrationsFlawRepository_GetOrgFromFlawID_Call) Return(_a0 models.Org, _a1 error) *IntegrationsFlawRepository_GetOrgFromFlawID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntegrationsFlawRepository_GetOrgFromFlawID_Call) RunAndReturn(run func(*gorm.DB, string) (models.Org, error)) *IntegrationsFlawRepository_GetOrgFromFlawID_Call {
	_c.Call.Return(run)
	return _c
}

// Read provides a mock function with given fields: id
func (_m *IntegrationsFlawRepository) Read(id string) (models.Flaw, error) {
	ret := _m.Called(id)

	if len(ret) == 0 {
		panic("no return value specified for Read")
	}

	var r0 models.Flaw
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (models.Flaw, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(string) models.Flaw); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(models.Flaw)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntegrationsFlawRepository_Read_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Read'
type IntegrationsFlawRepository_Read_Call struct {
	*mock.Call
}

// Read is a helper method to define mock.On call
//   - id string
func (_e *IntegrationsFlawRepository_Expecter) Read(id interface{}) *IntegrationsFlawRepository_Read_Call {
	return &IntegrationsFlawRepository_Read_Call{Call: _e.mock.On("Read", id)}
}

func (_c *IntegrationsFlawRepository_Read_Call) Run(run func(id string)) *IntegrationsFlawRepository_Read_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *IntegrationsFlawRepository_Read_Call) Return(_a0 models.Flaw, _a1 error) *IntegrationsFlawRepository_Read_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntegrationsFlawRepository_Read_Call) RunAndReturn(run func(string) (models.Flaw, error)) *IntegrationsFlawRepository_Read_Call {
	_c.Call.Return(run)
	return _c
}

// Save provides a mock function with given fields: db, flaw
func (_m *IntegrationsFlawRepository) Save(db *gorm.DB, flaw *models.Flaw) error {
	ret := _m.Called(db, flaw)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(*gorm.DB, *models.Flaw) error); ok {
		r0 = rf(db, flaw)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationsFlawRepository_Save_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Save'
type IntegrationsFlawRepository_Save_Call struct {
	*mock.Call
}

// Save is a helper method to define mock.On call
//   - db *gorm.DB
//   - flaw *models.Flaw
func (_e *IntegrationsFlawRepository_Expecter) Save(db interface{}, flaw interface{}) *IntegrationsFlawRepository_Save_Call {
	return &IntegrationsFlawRepository_Save_Call{Call: _e.mock.On("Save", db, flaw)}
}

func (_c *IntegrationsFlawRepository_Save_Call) Run(run func(db *gorm.DB, flaw *models.Flaw)) *IntegrationsFlawRepository_Save_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*gorm.DB), args[1].(*models.Flaw))
	})
	return _c
}

func (_c *IntegrationsFlawRepository_Save_Call) Return(_a0 error) *IntegrationsFlawRepository_Save_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationsFlawRepository_Save_Call) RunAndReturn(run func(*gorm.DB, *models.Flaw) error) *IntegrationsFlawRepository_Save_Call {
	_c.Call.Return(run)
	return _c
}

// Transaction provides a mock function with given fields: fn
func (_m *IntegrationsFlawRepository) Transaction(fn func(*gorm.DB) error) error {
	ret := _m.Called(fn)

	if len(ret) == 0 {
		panic("no return value specified for Transaction")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(func(*gorm.DB) error) error); ok {
		r0 = rf(fn)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IntegrationsFlawRepository_Transaction_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Transaction'
type IntegrationsFlawRepository_Transaction_Call struct {
	*mock.Call
}

// Transaction is a helper method to define mock.On call
//   - fn func(*gorm.DB) error
func (_e *IntegrationsFlawRepository_Expecter) Transaction(fn interface{}) *IntegrationsFlawRepository_Transaction_Call {
	return &IntegrationsFlawRepository_Transaction_Call{Call: _e.mock.On("Transaction", fn)}
}

func (_c *IntegrationsFlawRepository_Transaction_Call) Run(run func(fn func(*gorm.DB) error)) *IntegrationsFlawRepository_Transaction_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(func(*gorm.DB) error))
	})
	return _c
}

func (_c *IntegrationsFlawRepository_Transaction_Call) Return(_a0 error) *IntegrationsFlawRepository_Transaction_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *IntegrationsFlawRepository_Transaction_Call) RunAndReturn(run func(func(*gorm.DB) error) error) *IntegrationsFlawRepository_Transaction_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntegrationsFlawRepository creates a new instance of IntegrationsFlawRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntegrationsFlawRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntegrationsFlawRepository {
	mock := &IntegrationsFlawRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
