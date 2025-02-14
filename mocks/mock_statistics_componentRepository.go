// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// StatisticsComponentRepository is an autogenerated mock type for the componentRepository type
type StatisticsComponentRepository struct {
	mock.Mock
}

type StatisticsComponentRepository_Expecter struct {
	mock *mock.Mock
}

func (_m *StatisticsComponentRepository) EXPECT() *StatisticsComponentRepository_Expecter {
	return &StatisticsComponentRepository_Expecter{mock: &_m.Mock}
}

// GetDependencyCountPerscanner provides a mock function with given fields: assetID
func (_m *StatisticsComponentRepository) GetDependencyCountPerscanner(assetID uuid.UUID) (map[string]int, error) {
	ret := _m.Called(assetID)

	if len(ret) == 0 {
		panic("no return value specified for GetDependencyCountPerscanner")
	}

	var r0 map[string]int
	var r1 error
	if rf, ok := ret.Get(0).(func(uuid.UUID) (map[string]int, error)); ok {
		return rf(assetID)
	}
	if rf, ok := ret.Get(0).(func(uuid.UUID) map[string]int); ok {
		r0 = rf(assetID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]int)
		}
	}

	if rf, ok := ret.Get(1).(func(uuid.UUID) error); ok {
		r1 = rf(assetID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// StatisticsComponentRepository_GetDependencyCountPerscanner_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetDependencyCountPerscanner'
type StatisticsComponentRepository_GetDependencyCountPerscanner_Call struct {
	*mock.Call
}

// GetDependencyCountPerscanner is a helper method to define mock.On call
//   - assetID uuid.UUID
func (_e *StatisticsComponentRepository_Expecter) GetDependencyCountPerscanner(assetID interface{}) *StatisticsComponentRepository_GetDependencyCountPerscanner_Call {
	return &StatisticsComponentRepository_GetDependencyCountPerscanner_Call{Call: _e.mock.On("GetDependencyCountPerscanner", assetID)}
}

func (_c *StatisticsComponentRepository_GetDependencyCountPerscanner_Call) Run(run func(assetID uuid.UUID)) *StatisticsComponentRepository_GetDependencyCountPerscanner_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uuid.UUID))
	})
	return _c
}

func (_c *StatisticsComponentRepository_GetDependencyCountPerscanner_Call) Return(_a0 map[string]int, _a1 error) *StatisticsComponentRepository_GetDependencyCountPerscanner_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *StatisticsComponentRepository_GetDependencyCountPerscanner_Call) RunAndReturn(run func(uuid.UUID) (map[string]int, error)) *StatisticsComponentRepository_GetDependencyCountPerscanner_Call {
	_c.Call.Return(run)
	return _c
}

// NewStatisticsComponentRepository creates a new instance of StatisticsComponentRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStatisticsComponentRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *StatisticsComponentRepository {
	mock := &StatisticsComponentRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
