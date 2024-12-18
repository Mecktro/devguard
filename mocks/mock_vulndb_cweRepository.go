// Code generated by mockery v2.46.2. DO NOT EDIT.

package mocks

import (
	database "github.com/l3montree-dev/devguard/internal/database"
	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// VulndbCweRepository is an autogenerated mock type for the cweRepository type
type VulndbCweRepository struct {
	mock.Mock
}

type VulndbCweRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *VulndbCweRepository) EXPECT() *VulndbCweRepository_Expecter {
	return &VulndbCweRepository_Expecter{mock: &_m.Mock}
}

// SaveBatch provides a mock function with given fields: tx, cwes
func (_m *VulndbCweRepository) SaveBatch(tx database.DB, cwes []models.CWE) error {
	ret := _m.Called(tx, cwes)

	if len(ret) == 0 {
		panic("no return value specified for SaveBatch")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(database.DB, []models.CWE) error); ok {
		r0 = rf(tx, cwes)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// VulndbCweRepository_SaveBatch_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SaveBatch'
type VulndbCweRepository_SaveBatch_Call struct {
	*mock.Call
}

// SaveBatch is a helper method to define mock.On call
//   - tx database.DB
//   - cwes []models.CWE
func (_e *VulndbCweRepository_Expecter) SaveBatch(tx interface{}, cwes interface{}) *VulndbCweRepository_SaveBatch_Call {
	return &VulndbCweRepository_SaveBatch_Call{Call: _e.mock.On("SaveBatch", tx, cwes)}
}

func (_c *VulndbCweRepository_SaveBatch_Call) Run(run func(tx database.DB, cwes []models.CWE)) *VulndbCweRepository_SaveBatch_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(database.DB), args[1].([]models.CWE))
	})
	return _c
}

func (_c *VulndbCweRepository_SaveBatch_Call) Return(_a0 error) *VulndbCweRepository_SaveBatch_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *VulndbCweRepository_SaveBatch_Call) RunAndReturn(run func(database.DB, []models.CWE) error) *VulndbCweRepository_SaveBatch_Call {
	_c.Call.Return(run)
	return _c
}

// NewVulndbCweRepository creates a new instance of VulndbCweRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewVulndbCweRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *VulndbCweRepository {
	mock := &VulndbCweRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
