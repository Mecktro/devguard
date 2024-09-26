// Code generated by mockery v2.42.2. DO NOT EDIT.

package mocks

import (
	context "context"

	github "github.com/google/go-github/v62/github"

	mock "github.com/stretchr/testify/mock"
)

// IntegrationsGithubClientFacade is an autogenerated mock type for the githubClientFacade type
type IntegrationsGithubClientFacade struct {
	mock.Mock
}

type IntegrationsGithubClientFacade_Expecter struct {
	mock *mock.Mock
}

func (_m *IntegrationsGithubClientFacade) EXPECT() *IntegrationsGithubClientFacade_Expecter {
	return &IntegrationsGithubClientFacade_Expecter{mock: &_m.Mock}
}

// CreateIssue provides a mock function with given fields: ctx, owner, repo, issue
func (_m *IntegrationsGithubClientFacade) CreateIssue(ctx context.Context, owner string, repo string, issue *github.IssueRequest) (*github.Issue, *github.Response, error) {
	ret := _m.Called(ctx, owner, repo, issue)

	if len(ret) == 0 {
		panic("no return value specified for CreateIssue")
	}

	var r0 *github.Issue
	var r1 *github.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *github.IssueRequest) (*github.Issue, *github.Response, error)); ok {
		return rf(ctx, owner, repo, issue)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *github.IssueRequest) *github.Issue); ok {
		r0 = rf(ctx, owner, repo, issue)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*github.Issue)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, *github.IssueRequest) *github.Response); ok {
		r1 = rf(ctx, owner, repo, issue)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*github.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string, *github.IssueRequest) error); ok {
		r2 = rf(ctx, owner, repo, issue)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// IntegrationsGithubClientFacade_CreateIssue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateIssue'
type IntegrationsGithubClientFacade_CreateIssue_Call struct {
	*mock.Call
}

// CreateIssue is a helper method to define mock.On call
//   - ctx context.Context
//   - owner string
//   - repo string
//   - issue *github.IssueRequest
func (_e *IntegrationsGithubClientFacade_Expecter) CreateIssue(ctx interface{}, owner interface{}, repo interface{}, issue interface{}) *IntegrationsGithubClientFacade_CreateIssue_Call {
	return &IntegrationsGithubClientFacade_CreateIssue_Call{Call: _e.mock.On("CreateIssue", ctx, owner, repo, issue)}
}

func (_c *IntegrationsGithubClientFacade_CreateIssue_Call) Run(run func(ctx context.Context, owner string, repo string, issue *github.IssueRequest)) *IntegrationsGithubClientFacade_CreateIssue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(*github.IssueRequest))
	})
	return _c
}

func (_c *IntegrationsGithubClientFacade_CreateIssue_Call) Return(_a0 *github.Issue, _a1 *github.Response, _a2 error) *IntegrationsGithubClientFacade_CreateIssue_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *IntegrationsGithubClientFacade_CreateIssue_Call) RunAndReturn(run func(context.Context, string, string, *github.IssueRequest) (*github.Issue, *github.Response, error)) *IntegrationsGithubClientFacade_CreateIssue_Call {
	_c.Call.Return(run)
	return _c
}

// CreateIssueComment provides a mock function with given fields: ctx, owner, repo, number, comment
func (_m *IntegrationsGithubClientFacade) CreateIssueComment(ctx context.Context, owner string, repo string, number int, comment *github.IssueComment) (*github.IssueComment, *github.Response, error) {
	ret := _m.Called(ctx, owner, repo, number, comment)

	if len(ret) == 0 {
		panic("no return value specified for CreateIssueComment")
	}

	var r0 *github.IssueComment
	var r1 *github.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, int, *github.IssueComment) (*github.IssueComment, *github.Response, error)); ok {
		return rf(ctx, owner, repo, number, comment)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, int, *github.IssueComment) *github.IssueComment); ok {
		r0 = rf(ctx, owner, repo, number, comment)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*github.IssueComment)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, int, *github.IssueComment) *github.Response); ok {
		r1 = rf(ctx, owner, repo, number, comment)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*github.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string, int, *github.IssueComment) error); ok {
		r2 = rf(ctx, owner, repo, number, comment)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// IntegrationsGithubClientFacade_CreateIssueComment_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateIssueComment'
type IntegrationsGithubClientFacade_CreateIssueComment_Call struct {
	*mock.Call
}

// CreateIssueComment is a helper method to define mock.On call
//   - ctx context.Context
//   - owner string
//   - repo string
//   - number int
//   - comment *github.IssueComment
func (_e *IntegrationsGithubClientFacade_Expecter) CreateIssueComment(ctx interface{}, owner interface{}, repo interface{}, number interface{}, comment interface{}) *IntegrationsGithubClientFacade_CreateIssueComment_Call {
	return &IntegrationsGithubClientFacade_CreateIssueComment_Call{Call: _e.mock.On("CreateIssueComment", ctx, owner, repo, number, comment)}
}

func (_c *IntegrationsGithubClientFacade_CreateIssueComment_Call) Run(run func(ctx context.Context, owner string, repo string, number int, comment *github.IssueComment)) *IntegrationsGithubClientFacade_CreateIssueComment_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(int), args[4].(*github.IssueComment))
	})
	return _c
}

func (_c *IntegrationsGithubClientFacade_CreateIssueComment_Call) Return(_a0 *github.IssueComment, _a1 *github.Response, _a2 error) *IntegrationsGithubClientFacade_CreateIssueComment_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *IntegrationsGithubClientFacade_CreateIssueComment_Call) RunAndReturn(run func(context.Context, string, string, int, *github.IssueComment) (*github.IssueComment, *github.Response, error)) *IntegrationsGithubClientFacade_CreateIssueComment_Call {
	_c.Call.Return(run)
	return _c
}

// EditIssue provides a mock function with given fields: ctx, owner, repo, number, issue
func (_m *IntegrationsGithubClientFacade) EditIssue(ctx context.Context, owner string, repo string, number int, issue *github.IssueRequest) (*github.Issue, *github.Response, error) {
	ret := _m.Called(ctx, owner, repo, number, issue)

	if len(ret) == 0 {
		panic("no return value specified for EditIssue")
	}

	var r0 *github.Issue
	var r1 *github.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, int, *github.IssueRequest) (*github.Issue, *github.Response, error)); ok {
		return rf(ctx, owner, repo, number, issue)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, int, *github.IssueRequest) *github.Issue); ok {
		r0 = rf(ctx, owner, repo, number, issue)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*github.Issue)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, int, *github.IssueRequest) *github.Response); ok {
		r1 = rf(ctx, owner, repo, number, issue)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*github.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string, int, *github.IssueRequest) error); ok {
		r2 = rf(ctx, owner, repo, number, issue)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// IntegrationsGithubClientFacade_EditIssue_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EditIssue'
type IntegrationsGithubClientFacade_EditIssue_Call struct {
	*mock.Call
}

// EditIssue is a helper method to define mock.On call
//   - ctx context.Context
//   - owner string
//   - repo string
//   - number int
//   - issue *github.IssueRequest
func (_e *IntegrationsGithubClientFacade_Expecter) EditIssue(ctx interface{}, owner interface{}, repo interface{}, number interface{}, issue interface{}) *IntegrationsGithubClientFacade_EditIssue_Call {
	return &IntegrationsGithubClientFacade_EditIssue_Call{Call: _e.mock.On("EditIssue", ctx, owner, repo, number, issue)}
}

func (_c *IntegrationsGithubClientFacade_EditIssue_Call) Run(run func(ctx context.Context, owner string, repo string, number int, issue *github.IssueRequest)) *IntegrationsGithubClientFacade_EditIssue_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(int), args[4].(*github.IssueRequest))
	})
	return _c
}

func (_c *IntegrationsGithubClientFacade_EditIssue_Call) Return(_a0 *github.Issue, _a1 *github.Response, _a2 error) *IntegrationsGithubClientFacade_EditIssue_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *IntegrationsGithubClientFacade_EditIssue_Call) RunAndReturn(run func(context.Context, string, string, int, *github.IssueRequest) (*github.Issue, *github.Response, error)) *IntegrationsGithubClientFacade_EditIssue_Call {
	_c.Call.Return(run)
	return _c
}

// EditIssueLabel provides a mock function with given fields: ctx, owner, repo, name, label
func (_m *IntegrationsGithubClientFacade) EditIssueLabel(ctx context.Context, owner string, repo string, name string, label *github.Label) (*github.Label, *github.Response, error) {
	ret := _m.Called(ctx, owner, repo, name, label)

	if len(ret) == 0 {
		panic("no return value specified for EditIssueLabel")
	}

	var r0 *github.Label
	var r1 *github.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, *github.Label) (*github.Label, *github.Response, error)); ok {
		return rf(ctx, owner, repo, name, label)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, *github.Label) *github.Label); ok {
		r0 = rf(ctx, owner, repo, name, label)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*github.Label)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, *github.Label) *github.Response); ok {
		r1 = rf(ctx, owner, repo, name, label)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*github.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string, string, *github.Label) error); ok {
		r2 = rf(ctx, owner, repo, name, label)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// IntegrationsGithubClientFacade_EditIssueLabel_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EditIssueLabel'
type IntegrationsGithubClientFacade_EditIssueLabel_Call struct {
	*mock.Call
}

// EditIssueLabel is a helper method to define mock.On call
//   - ctx context.Context
//   - owner string
//   - repo string
//   - name string
//   - label *github.Label
func (_e *IntegrationsGithubClientFacade_Expecter) EditIssueLabel(ctx interface{}, owner interface{}, repo interface{}, name interface{}, label interface{}) *IntegrationsGithubClientFacade_EditIssueLabel_Call {
	return &IntegrationsGithubClientFacade_EditIssueLabel_Call{Call: _e.mock.On("EditIssueLabel", ctx, owner, repo, name, label)}
}

func (_c *IntegrationsGithubClientFacade_EditIssueLabel_Call) Run(run func(ctx context.Context, owner string, repo string, name string, label *github.Label)) *IntegrationsGithubClientFacade_EditIssueLabel_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(string), args[4].(*github.Label))
	})
	return _c
}

func (_c *IntegrationsGithubClientFacade_EditIssueLabel_Call) Return(_a0 *github.Label, _a1 *github.Response, _a2 error) *IntegrationsGithubClientFacade_EditIssueLabel_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *IntegrationsGithubClientFacade_EditIssueLabel_Call) RunAndReturn(run func(context.Context, string, string, string, *github.Label) (*github.Label, *github.Response, error)) *IntegrationsGithubClientFacade_EditIssueLabel_Call {
	_c.Call.Return(run)
	return _c
}

// NewIntegrationsGithubClientFacade creates a new instance of IntegrationsGithubClientFacade. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIntegrationsGithubClientFacade(t interface {
	mock.TestingT
	Cleanup(func())
}) *IntegrationsGithubClientFacade {
	mock := &IntegrationsGithubClientFacade{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
