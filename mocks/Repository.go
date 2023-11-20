// Code generated by mockery v2.36.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// Repository is an autogenerated mock type for the Repository type
type Repository[ID interface{}, T interface{}] struct {
	mock.Mock
}

// Create provides a mock function with given fields: t
func (_m *Repository[ID, T]) Create(t *T) error {
	ret := _m.Called(t)

	var r0 error
	if rf, ok := ret.Get(0).(func(*T) error); ok {
		r0 = rf(t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Delete provides a mock function with given fields: id
func (_m *Repository[ID, T]) Delete(id ID) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(ID) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// List provides a mock function with given fields: ids
func (_m *Repository[ID, T]) List(ids []ID) ([]T, error) {
	ret := _m.Called(ids)

	var r0 []T
	var r1 error
	if rf, ok := ret.Get(0).(func([]ID) ([]T, error)); ok {
		return rf(ids)
	}
	if rf, ok := ret.Get(0).(func([]ID) []T); ok {
		r0 = rf(ids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]T)
		}
	}

	if rf, ok := ret.Get(1).(func([]ID) error); ok {
		r1 = rf(ids)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Read provides a mock function with given fields: id
func (_m *Repository[ID, T]) Read(id ID) (T, error) {
	ret := _m.Called(id)

	var r0 T
	var r1 error
	if rf, ok := ret.Get(0).(func(ID) (T, error)); ok {
		return rf(id)
	}
	if rf, ok := ret.Get(0).(func(ID) T); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Get(0).(T)
	}

	if rf, ok := ret.Get(1).(func(ID) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Update provides a mock function with given fields: t
func (_m *Repository[ID, T]) Update(t *T) error {
	ret := _m.Called(t)

	var r0 error
	if rf, ok := ret.Get(0).(func(*T) error); ok {
		r0 = rf(t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewRepository creates a new instance of Repository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewRepository[ID interface{}, T interface{}](t interface {
	mock.TestingT
	Cleanup(func())
}) *Repository[ID, T] {
	mock := &Repository[ID, T]{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
