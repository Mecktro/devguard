// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	context "context"

	core "github.com/l3montree-dev/devguard/internal/core"
	echo "github.com/labstack/echo/v4"

	mock "github.com/stretchr/testify/mock"

	models "github.com/l3montree-dev/devguard/internal/database/models"
)

// CoreThirdPartyIntegration is an autogenerated mock type for the ThirdPartyIntegration type
type CoreThirdPartyIntegration struct {
	mock.Mock
}

type CoreThirdPartyIntegration_Expecter struct {
	mock *mock.Mock
}

func (_m *CoreThirdPartyIntegration) EXPECT() *CoreThirdPartyIntegration_Expecter {
	return &CoreThirdPartyIntegration_Expecter{mock: &_m.Mock}
}

// CloseIssue provides a mock function with given fields: ctx, state, repoId, dependencyVuln
func (_m *CoreThirdPartyIntegration) CloseIssue(ctx context.Context, state string, repoId string, dependencyVuln models.DependencyVuln) error {
	ret := _m.Called(ctx, state, repoId, dependencyVuln)

	if len(ret) == 0 {
		panic("no return value specified for CloseIssue")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, models.DependencyVuln) error); ok {
		r0 = rf(ctx, state, repoId, dependencyVuln)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreThirdPartyIntegration_CloseIssue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CloseIssue'
type CoreThirdPartyIntegration_CloseIssue_Call struct {
	*mock.Call
}

// CloseIssue is a helper method to define mock.On call
//   - ctx context.Context
//   - state string
//   - repoId string
//   - dependencyVuln models.DependencyVuln
func (_e *CoreThirdPartyIntegration_Expecter) CloseIssue(ctx interface{}, state interface{}, repoId interface{}, dependencyVuln interface{}) *CoreThirdPartyIntegration_CloseIssue_Call {
	return &CoreThirdPartyIntegration_CloseIssue_Call{Call: _e.mock.On("CloseIssue", ctx, state, repoId, dependencyVuln)}
}

func (_c *CoreThirdPartyIntegration_CloseIssue_Call) Run(run func(ctx context.Context, state string, repoId string, dependencyVuln models.DependencyVuln)) *CoreThirdPartyIntegration_CloseIssue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(models.DependencyVuln))
	})
	return _c
}

func (_c *CoreThirdPartyIntegration_CloseIssue_Call) Return(_a0 error) *CoreThirdPartyIntegration_CloseIssue_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreThirdPartyIntegration_CloseIssue_Call) RunAndReturn(run func(context.Context, string, string, models.DependencyVuln) error) *CoreThirdPartyIntegration_CloseIssue_Call {
	_c.Call.Return(run)
	return _c
}

// CreateIssue provides a mock function with given fields: ctx, asset, assetVersionName, repoId, dependencyVuln, projectSlug, orgSlug
func (_m *CoreThirdPartyIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, repoId string, dependencyVuln models.DependencyVuln, projectSlug string, orgSlug string) error {
	ret := _m.Called(ctx, asset, assetVersionName, repoId, dependencyVuln, projectSlug, orgSlug)

	if len(ret) == 0 {
		panic("no return value specified for CreateIssue")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, models.Asset, string, string, models.DependencyVuln, string, string) error); ok {
		r0 = rf(ctx, asset, assetVersionName, repoId, dependencyVuln, projectSlug, orgSlug)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreThirdPartyIntegration_CreateIssue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateIssue'
type CoreThirdPartyIntegration_CreateIssue_Call struct {
	*mock.Call
}

// CreateIssue is a helper method to define mock.On call
//   - ctx context.Context
//   - asset models.Asset
//   - assetVersionName string
//   - repoId string
//   - dependencyVuln models.DependencyVuln
//   - projectSlug string
//   - orgSlug string
func (_e *CoreThirdPartyIntegration_Expecter) CreateIssue(ctx interface{}, asset interface{}, assetVersionName interface{}, repoId interface{}, dependencyVuln interface{}, projectSlug interface{}, orgSlug interface{}) *CoreThirdPartyIntegration_CreateIssue_Call {
	return &CoreThirdPartyIntegration_CreateIssue_Call{Call: _e.mock.On("CreateIssue", ctx, asset, assetVersionName, repoId, dependencyVuln, projectSlug, orgSlug)}
}

func (_c *CoreThirdPartyIntegration_CreateIssue_Call) Run(run func(ctx context.Context, asset models.Asset, assetVersionName string, repoId string, dependencyVuln models.DependencyVuln, projectSlug string, orgSlug string)) *CoreThirdPartyIntegration_CreateIssue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(models.Asset), args[2].(string), args[3].(string), args[4].(models.DependencyVuln), args[5].(string), args[6].(string))
	})
	return _c
}

func (_c *CoreThirdPartyIntegration_CreateIssue_Call) Return(_a0 error) *CoreThirdPartyIntegration_CreateIssue_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreThirdPartyIntegration_CreateIssue_Call) RunAndReturn(run func(context.Context, models.Asset, string, string, models.DependencyVuln, string, string) error) *CoreThirdPartyIntegration_CreateIssue_Call {
	_c.Call.Return(run)
	return _c
}

// GetID provides a mock function with no fields
func (_m *CoreThirdPartyIntegration) GetID() core.IntegrationID {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetID")
	}

	var r0 core.IntegrationID
	if rf, ok := ret.Get(0).(func() core.IntegrationID); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(core.IntegrationID)
	}

	return r0
}

// CoreThirdPartyIntegration_GetID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetID'
type CoreThirdPartyIntegration_GetID_Call struct {
	*mock.Call
}

// GetID is a helper method to define mock.On call
func (_e *CoreThirdPartyIntegration_Expecter) GetID() *CoreThirdPartyIntegration_GetID_Call {
	return &CoreThirdPartyIntegration_GetID_Call{Call: _e.mock.On("GetID")}
}

func (_c *CoreThirdPartyIntegration_GetID_Call) Run(run func()) *CoreThirdPartyIntegration_GetID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *CoreThirdPartyIntegration_GetID_Call) Return(_a0 core.IntegrationID) *CoreThirdPartyIntegration_GetID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreThirdPartyIntegration_GetID_Call) RunAndReturn(run func() core.IntegrationID) *CoreThirdPartyIntegration_GetID_Call {
	_c.Call.Return(run)
	return _c
}

// GetUsers provides a mock function with given fields: org
func (_m *CoreThirdPartyIntegration) GetUsers(org models.Org) []core.User {
	ret := _m.Called(org)

	if len(ret) == 0 {
		panic("no return value specified for GetUsers")
	}

	var r0 []core.User
	if rf, ok := ret.Get(0).(func(models.Org) []core.User); ok {
		r0 = rf(org)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]core.User)
		}
	}

	return r0
}

// CoreThirdPartyIntegration_GetUsers_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUsers'
type CoreThirdPartyIntegration_GetUsers_Call struct {
	*mock.Call
}

// GetUsers is a helper method to define mock.On call
//   - org models.Org
func (_e *CoreThirdPartyIntegration_Expecter) GetUsers(org interface{}) *CoreThirdPartyIntegration_GetUsers_Call {
	return &CoreThirdPartyIntegration_GetUsers_Call{Call: _e.mock.On("GetUsers", org)}
}

func (_c *CoreThirdPartyIntegration_GetUsers_Call) Run(run func(org models.Org)) *CoreThirdPartyIntegration_GetUsers_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(models.Org))
	})
	return _c
}

func (_c *CoreThirdPartyIntegration_GetUsers_Call) Return(_a0 []core.User) *CoreThirdPartyIntegration_GetUsers_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreThirdPartyIntegration_GetUsers_Call) RunAndReturn(run func(models.Org) []core.User) *CoreThirdPartyIntegration_GetUsers_Call {
	_c.Call.Return(run)
	return _c
}

// HandleEvent provides a mock function with given fields: event
func (_m *CoreThirdPartyIntegration) HandleEvent(event interface{}) error {
	ret := _m.Called(event)

	if len(ret) == 0 {
		panic("no return value specified for HandleEvent")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(interface{}) error); ok {
		r0 = rf(event)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreThirdPartyIntegration_HandleEvent_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleEvent'
type CoreThirdPartyIntegration_HandleEvent_Call struct {
	*mock.Call
}

// HandleEvent is a helper method to define mock.On call
//   - event interface{}
func (_e *CoreThirdPartyIntegration_Expecter) HandleEvent(event interface{}) *CoreThirdPartyIntegration_HandleEvent_Call {
	return &CoreThirdPartyIntegration_HandleEvent_Call{Call: _e.mock.On("HandleEvent", event)}
}

func (_c *CoreThirdPartyIntegration_HandleEvent_Call) Run(run func(event interface{})) *CoreThirdPartyIntegration_HandleEvent_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(interface{}))
	})
	return _c
}

func (_c *CoreThirdPartyIntegration_HandleEvent_Call) Return(_a0 error) *CoreThirdPartyIntegration_HandleEvent_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreThirdPartyIntegration_HandleEvent_Call) RunAndReturn(run func(interface{}) error) *CoreThirdPartyIntegration_HandleEvent_Call {
	_c.Call.Return(run)
	return _c
}

// HandleWebhook provides a mock function with given fields: ctx
func (_m *CoreThirdPartyIntegration) HandleWebhook(ctx echo.Context) error {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for HandleWebhook")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(echo.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreThirdPartyIntegration_HandleWebhook_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'HandleWebhook'
type CoreThirdPartyIntegration_HandleWebhook_Call struct {
	*mock.Call
}

// HandleWebhook is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *CoreThirdPartyIntegration_Expecter) HandleWebhook(ctx interface{}) *CoreThirdPartyIntegration_HandleWebhook_Call {
	return &CoreThirdPartyIntegration_HandleWebhook_Call{Call: _e.mock.On("HandleWebhook", ctx)}
}

func (_c *CoreThirdPartyIntegration_HandleWebhook_Call) Run(run func(ctx echo.Context)) *CoreThirdPartyIntegration_HandleWebhook_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *CoreThirdPartyIntegration_HandleWebhook_Call) Return(_a0 error) *CoreThirdPartyIntegration_HandleWebhook_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreThirdPartyIntegration_HandleWebhook_Call) RunAndReturn(run func(echo.Context) error) *CoreThirdPartyIntegration_HandleWebhook_Call {
	_c.Call.Return(run)
	return _c
}

// IntegrationEnabled provides a mock function with given fields: ctx
func (_m *CoreThirdPartyIntegration) IntegrationEnabled(ctx echo.Context) bool {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for IntegrationEnabled")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(echo.Context) bool); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// CoreThirdPartyIntegration_IntegrationEnabled_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IntegrationEnabled'
type CoreThirdPartyIntegration_IntegrationEnabled_Call struct {
	*mock.Call
}

// IntegrationEnabled is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *CoreThirdPartyIntegration_Expecter) IntegrationEnabled(ctx interface{}) *CoreThirdPartyIntegration_IntegrationEnabled_Call {
	return &CoreThirdPartyIntegration_IntegrationEnabled_Call{Call: _e.mock.On("IntegrationEnabled", ctx)}
}

func (_c *CoreThirdPartyIntegration_IntegrationEnabled_Call) Run(run func(ctx echo.Context)) *CoreThirdPartyIntegration_IntegrationEnabled_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *CoreThirdPartyIntegration_IntegrationEnabled_Call) Return(_a0 bool) *CoreThirdPartyIntegration_IntegrationEnabled_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreThirdPartyIntegration_IntegrationEnabled_Call) RunAndReturn(run func(echo.Context) bool) *CoreThirdPartyIntegration_IntegrationEnabled_Call {
	_c.Call.Return(run)
	return _c
}

// ListRepositories provides a mock function with given fields: ctx
func (_m *CoreThirdPartyIntegration) ListRepositories(ctx echo.Context) ([]core.Repository, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for ListRepositories")
	}

	var r0 []core.Repository
	var r1 error
	if rf, ok := ret.Get(0).(func(echo.Context) ([]core.Repository, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(echo.Context) []core.Repository); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]core.Repository)
		}
	}

	if rf, ok := ret.Get(1).(func(echo.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CoreThirdPartyIntegration_ListRepositories_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListRepositories'
type CoreThirdPartyIntegration_ListRepositories_Call struct {
	*mock.Call
}

// ListRepositories is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *CoreThirdPartyIntegration_Expecter) ListRepositories(ctx interface{}) *CoreThirdPartyIntegration_ListRepositories_Call {
	return &CoreThirdPartyIntegration_ListRepositories_Call{Call: _e.mock.On("ListRepositories", ctx)}
}

func (_c *CoreThirdPartyIntegration_ListRepositories_Call) Run(run func(ctx echo.Context)) *CoreThirdPartyIntegration_ListRepositories_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *CoreThirdPartyIntegration_ListRepositories_Call) Return(_a0 []core.Repository, _a1 error) *CoreThirdPartyIntegration_ListRepositories_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *CoreThirdPartyIntegration_ListRepositories_Call) RunAndReturn(run func(echo.Context) ([]core.Repository, error)) *CoreThirdPartyIntegration_ListRepositories_Call {
	_c.Call.Return(run)
	return _c
}

// ReopenIssue provides a mock function with given fields: ctx, repoId, dependencyVuln
func (_m *CoreThirdPartyIntegration) ReopenIssue(ctx context.Context, repoId string, dependencyVuln models.DependencyVuln) error {
	ret := _m.Called(ctx, repoId, dependencyVuln)

	if len(ret) == 0 {
		panic("no return value specified for ReopenIssue")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, models.DependencyVuln) error); ok {
		r0 = rf(ctx, repoId, dependencyVuln)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CoreThirdPartyIntegration_ReopenIssue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReopenIssue'
type CoreThirdPartyIntegration_ReopenIssue_Call struct {
	*mock.Call
}

// ReopenIssue is a helper method to define mock.On call
//   - ctx context.Context
//   - repoId string
//   - dependencyVuln models.DependencyVuln
func (_e *CoreThirdPartyIntegration_Expecter) ReopenIssue(ctx interface{}, repoId interface{}, dependencyVuln interface{}) *CoreThirdPartyIntegration_ReopenIssue_Call {
	return &CoreThirdPartyIntegration_ReopenIssue_Call{Call: _e.mock.On("ReopenIssue", ctx, repoId, dependencyVuln)}
}

func (_c *CoreThirdPartyIntegration_ReopenIssue_Call) Run(run func(ctx context.Context, repoId string, dependencyVuln models.DependencyVuln)) *CoreThirdPartyIntegration_ReopenIssue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(models.DependencyVuln))
	})
	return _c
}

func (_c *CoreThirdPartyIntegration_ReopenIssue_Call) Return(_a0 error) *CoreThirdPartyIntegration_ReopenIssue_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreThirdPartyIntegration_ReopenIssue_Call) RunAndReturn(run func(context.Context, string, models.DependencyVuln) error) *CoreThirdPartyIntegration_ReopenIssue_Call {
	_c.Call.Return(run)
	return _c
}

// WantsToHandleWebhook provides a mock function with given fields: ctx
func (_m *CoreThirdPartyIntegration) WantsToHandleWebhook(ctx echo.Context) bool {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for WantsToHandleWebhook")
	}

	var r0 bool
	if rf, ok := ret.Get(0).(func(echo.Context) bool); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// CoreThirdPartyIntegration_WantsToHandleWebhook_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WantsToHandleWebhook'
type CoreThirdPartyIntegration_WantsToHandleWebhook_Call struct {
	*mock.Call
}

// WantsToHandleWebhook is a helper method to define mock.On call
//   - ctx echo.Context
func (_e *CoreThirdPartyIntegration_Expecter) WantsToHandleWebhook(ctx interface{}) *CoreThirdPartyIntegration_WantsToHandleWebhook_Call {
	return &CoreThirdPartyIntegration_WantsToHandleWebhook_Call{Call: _e.mock.On("WantsToHandleWebhook", ctx)}
}

func (_c *CoreThirdPartyIntegration_WantsToHandleWebhook_Call) Run(run func(ctx echo.Context)) *CoreThirdPartyIntegration_WantsToHandleWebhook_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(echo.Context))
	})
	return _c
}

func (_c *CoreThirdPartyIntegration_WantsToHandleWebhook_Call) Return(_a0 bool) *CoreThirdPartyIntegration_WantsToHandleWebhook_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *CoreThirdPartyIntegration_WantsToHandleWebhook_Call) RunAndReturn(run func(echo.Context) bool) *CoreThirdPartyIntegration_WantsToHandleWebhook_Call {
	_c.Call.Return(run)
	return _c
}

// NewCoreThirdPartyIntegration creates a new instance of CoreThirdPartyIntegration. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCoreThirdPartyIntegration(t interface {
	mock.TestingT
	Cleanup(func())
}) *CoreThirdPartyIntegration {
	mock := &CoreThirdPartyIntegration{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
