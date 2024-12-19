// Code generated by mockery v2.46.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// IntotoSupplyChainRepositoryS is an autogenerated mock type for the supplyChainRepositoryS type
type IntotoSupplyChainRepositoryS struct {
	mock.Mock
}

type IntotoSupplyChainRepositoryS_Expecter struct {
	mock *mock.Mock
}

func (_m *IntotoSupplyChainRepositoryS) EXPECT() *IntotoSupplyChainRepositoryS_Expecter {
	return &IntotoSupplyChainRepositoryS_Expecter{mock: &_m.Mock}
}

// FindBySupplyChainID provides a mock function with given fields: supplyChainID
func (_m *IntotoSupplyChainRepositoryS) FindBySupplyChainID(supplyChainID string) ([]models.SupplyChain, error) {
	ret := _m.Called(supplyChainID)

	if len(ret) == 0 {
		panic("no return value specified for FindBySupplyChainID")
	}

	var r0 []models.SupplyChain
	var r1 error
	if rf, ok := ret.Get(0).(func(string) ([]models.SupplyChain, error)); ok {
		return rf(supplyChainID)
	}
	if rf, ok := ret.Get(0).(func(string) []models.SupplyChain); ok {
		r0 = rf(supplyChainID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.SupplyChain)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(supplyChainID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntotoSupplyChainRepositoryS_FindBySupplyChainID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindBySupplyChainID'
type IntotoSupplyChainRepositoryS_FindBySupplyChainID_Call struct {
	*mock.Call
}

// FindBySupplyChainID is a helper method to define mock.On call
//   - supplyChainID string
func (_e *IntotoSupplyChainRepositoryS_Expecter) FindBySupplyChainID(supplyChainID interface{}) *IntotoSupplyChainRepositoryS_FindBySupplyChainID_Call {
	return &IntotoSupplyChainRepositoryS_FindBySupplyChainID_Call{Call: _e.mock.On("FindBySupplyChainID", supplyChainID)}
}

func (_c *IntotoSupplyChainRepositoryS_FindBySupplyChainID_Call) Run(run func(supplyChainID string)) *IntotoSupplyChainRepositoryS_FindBySupplyChainID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *IntotoSupplyChainRepositoryS_FindBySupplyChainID_Call) Return(_a0 []models.SupplyChain, _a1 error) *IntotoSupplyChainRepositoryS_FindBySupplyChainID_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntotoSupplyChainRepositoryS_FindBySupplyChainID_Call) RunAndReturn(run func(string) ([]models.SupplyChain, error)) *IntotoSupplyChainRepositoryS_FindBySupplyChainID_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntotoSupplyChainRepositoryS creates a new instance of IntotoSupplyChainRepositoryS. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntotoSupplyChainRepositoryS(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntotoSupplyChainRepositoryS {
	mock := &IntotoSupplyChainRepositoryS{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
