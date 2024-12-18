// Code generated by mockery v2.46.2. DO NOT EDIT.

package mocks

import (
	models "github.com/l3montree-dev/devguard/internal/database/models"
	mock "github.com/stretchr/testify/mock"
)

// IntotoInTotoLinkRepository is an autogenerated mock type for the inTotoLinkRepository type
type IntotoInTotoLinkRepository struct {
	mock.Mock
}

type IntotoInTotoLinkRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *IntotoInTotoLinkRepository) EXPECT() *IntotoInTotoLinkRepository_Expecter {
	return &IntotoInTotoLinkRepository_Expecter{mock: &_m.Mock}
}

// FindBySupplyChainId provides a mock function with given fields: supplyChainId
func (_m *IntotoInTotoLinkRepository) FindBySupplyChainId(supplyChainId string) ([]models.InTotoLink, error) {
	ret := _m.Called(supplyChainId)

	if len(ret) == 0 {
		panic("no return value specified for FindBySupplyChainId")
	}

	var r0 []models.InTotoLink
	var r1 error
	if rf, ok := ret.Get(0).(func(string) ([]models.InTotoLink, error)); ok {
		return rf(supplyChainId)
	}
	if rf, ok := ret.Get(0).(func(string) []models.InTotoLink); ok {
		r0 = rf(supplyChainId)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.InTotoLink)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(supplyChainId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IntotoInTotoLinkRepository_FindBySupplyChainId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FindBySupplyChainId'
type IntotoInTotoLinkRepository_FindBySupplyChainId_Call struct {
	*mock.Call
}

// FindBySupplyChainId is a helper method to define mock.On call
//   - supplyChainId string
func (_e *IntotoInTotoLinkRepository_Expecter) FindBySupplyChainId(supplyChainId interface{}) *IntotoInTotoLinkRepository_FindBySupplyChainId_Call {
	return &IntotoInTotoLinkRepository_FindBySupplyChainId_Call{Call: _e.mock.On("FindBySupplyChainId", supplyChainId)}
}

func (_c *IntotoInTotoLinkRepository_FindBySupplyChainId_Call) Run(run func(supplyChainId string)) *IntotoInTotoLinkRepository_FindBySupplyChainId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *IntotoInTotoLinkRepository_FindBySupplyChainId_Call) Return(_a0 []models.InTotoLink, _a1 error) *IntotoInTotoLinkRepository_FindBySupplyChainId_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *IntotoInTotoLinkRepository_FindBySupplyChainId_Call) RunAndReturn(run func(string) ([]models.InTotoLink, error)) *IntotoInTotoLinkRepository_FindBySupplyChainId_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntotoInTotoLinkRepository creates a new instance of IntotoInTotoLinkRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntotoInTotoLinkRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntotoInTotoLinkRepository {
	mock := &IntotoInTotoLinkRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
