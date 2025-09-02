package models

import (
	"fmt"
	"log"
	"time"

	"github.com/saschazar21/go-oidc-provider/utils"
	"github.com/uptrace/bun"
)

type tokenQuery struct {
	query *bun.SelectQuery
}

func newTokenQuery(db bun.IDB, value string, tokenType string) *tokenQuery {
	if value == "" {
		return &tokenQuery{query: nil}
	}

	hashedValue := utils.HashedString(value)

	query := db.NewSelect().
		Model((*Token)(nil)).
		Where("\"token\".\"token_value\" = ?", hashedValue).
		Where("\"token\".\"is_active\" = ?", true).
		Where("\"token\".\"revoked_at\" IS NULL").
		Where("\"token\".\"expires_at\" > ?", time.Now().UTC())

	if tokenType != "" {
		query = query.Where("\"token\".\"token_type\" = ?", tokenType)
	}

	return &tokenQuery{query: query}
}

func (tq *tokenQuery) addAuthorization(isMandatory bool, isPopulated bool, name ...string) *tokenQuery {
	if tq.query == nil {
		return tq
	}

	n := "Authorization"
	alias := "authorization"
	owner := "token"
	if len(name) > 0 && name[0] != "" {
		n = name[0]
		alias = name[1]
		owner = name[2]
	}

	tq.query = tq.query.
		Relation(n, func(q *bun.SelectQuery) *bun.SelectQuery {
			excludeColumns := []string{"created_at", "expires_at"}

			if !isMandatory {
				q.
					WhereGroup(" AND ", func(sq *bun.SelectQuery) *bun.SelectQuery {
						return sq.
							Where(fmt.Sprintf("\"%s\".\"authorization_id\" IS NULL", owner)).
							WhereGroup(" OR ", func(sq *bun.SelectQuery) *bun.SelectQuery {
								return addAuthorizationConditions(sq, alias)
							})
					})
			} else {
				addAuthorizationConditions(q, alias).
					Where(fmt.Sprintf("\"%s\".\"authorization_id\" IS NOT NULL", owner))
			}

			return q.ExcludeColumn(excludeColumns...)
		})

	if isPopulated {
		tq = tq.
			addClient(isMandatory, "Authorization.Client", "authorization__client", alias).
			addUser(isMandatory, "Authorization.User", "authorization__user", alias)
	}

	return tq
}

func (tq *tokenQuery) addClient(isMandatory bool, name ...string) *tokenQuery {
	if tq.query == nil {
		return tq
	}

	n := "Client"
	alias := "client"
	owner := ""
	if len(name) > 0 && name[0] != "" {
		n = name[0]
		alias = name[1]
		owner = name[2]
	}

	if owner == "" {
		log.Fatalf("Owner table name is required for client relation.")
	}

	tq.query = tq.query.
		Relation(n, func(sq *bun.SelectQuery) *bun.SelectQuery {
			excludeColumns := []string{"client_secret", "created_at", "updated_at"}

			if !isMandatory {
				sq.
					WhereGroup(" AND ", func(sq *bun.SelectQuery) *bun.SelectQuery {
						return sq.
							Where(fmt.Sprintf("\"%s\".\"client_id\" IS NULL", owner)).
							WhereOr(fmt.Sprintf("\"%s\".\"is_active\" = ?", alias), true)
					})
			} else {
				sq.
					Where(fmt.Sprintf("\"%s\".\"client_id\" IS NOT NULL", owner)).
					Where(fmt.Sprintf("\"%s\".\"is_active\" = ?", alias), true)
			}

			return sq.ExcludeColumn(excludeColumns...)
		})

	return tq
}

func (tq *tokenQuery) addUser(isMandatory bool, name ...string) *tokenQuery {
	if tq.query == nil {
		return tq
	}

	n := "User"
	alias := "user"
	owner := ""
	if len(name) > 0 && name[0] != "" {
		n = name[0]
		alias = name[1]
		owner = name[2]
	}

	if owner == "" {
		log.Fatalf("Owner table name is required for user relation.")
	}

	tq.query = tq.query.
		Relation(n, func(sq *bun.SelectQuery) *bun.SelectQuery {
			excludeColumns := []string{"created_at", "updated_at", "email_hash"}

			if !isMandatory {
				sq.
					WhereGroup(" AND ", func(sq *bun.SelectQuery) *bun.SelectQuery {
						return sq.
							Where(fmt.Sprintf("\"%s\".\"user_id\" IS NULL", owner)).
							WhereGroup(" OR ", func(sq *bun.SelectQuery) *bun.SelectQuery {
								return sq.
									Where(fmt.Sprintf("\"%s\".\"is_active\" = ?", alias), true).
									Where(fmt.Sprintf("\"%s\".\"is_locked\" = ?", alias), false)
							})
					})
			} else {
				sq.
					Where(fmt.Sprintf("\"%s\".\"user_id\" IS NOT NULL", owner)).
					Where(fmt.Sprintf("\"%s\".\"is_active\" = ?", alias), true).
					Where(fmt.Sprintf("\"%s\".\"is_locked\" = ?", alias), false)
			}
			return sq.ExcludeColumn(excludeColumns...)
		})

	return tq
}

func addAuthorizationConditions(sq *bun.SelectQuery, alias ...string) *bun.SelectQuery {
	a := "authorization"
	if len(alias) > 0 && alias[0] != "" {
		a = alias[0]
	}

	return sq.
		Where(fmt.Sprintf("\"%s\".\"status\" = ?", a), "approved").
		Where(fmt.Sprintf("\"%s\".\"is_active\" = ?", a), true).
		Where(fmt.Sprintf("\"%s\".\"expires_at\" > ?", a), time.Now().UTC()).
		Where(fmt.Sprintf("\"%s\".\"revoked_at\" IS NULL", a))
}
