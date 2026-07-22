# Ruby and Rails Code Review Guide

> Code review guidance for Ruby 3.4+/4.0 and Rails 8.x, with emphasis on Ruby semantics, controller boundaries, Active Record correctness, query performance, background jobs, and tests.

## Table of Contents

- [Scope and Version Awareness](#scope-and-version-awareness)
- [Ruby Semantics and API Contracts](#ruby-semantics-and-api-contracts)
- [Collections, Mutation, and Nil](#collections-mutation-and-nil)
- [Exceptions and Resource Safety](#exceptions-and-resource-safety)
- [Rails Controllers and Security](#rails-controllers-and-security)
- [Active Record Correctness](#active-record-correctness)
- [Query Performance](#query-performance)
- [Transactions and Concurrency](#transactions-and-concurrency)
- [Active Job and External Side Effects](#active-job-and-external-side-effects)
- [Testing and Tooling](#testing-and-tooling)
- [Review Checklist](#review-checklist)
- [References](#references)

---

## Scope and Version Awareness

This guide targets maintained Ruby 3.4/4.0 applications and Rails 8.x. Before applying version-specific advice, inspect `.ruby-version`, `Gemfile.lock`, `config.load_defaults`, the database adapter, queue adapter, and CI matrix.

Do not require a newer API only because it exists. For example, Rails 8's `params.expect` is a concise strong-parameters API, while an existing explicit `require(...).permit(...)` contract can still be correct. Ruby implementation details also differ across MRI, JRuby, and TruffleRuby, so do not treat MRI's Global VM Lock as a substitute for synchronization.

Review questions:
- Which Ruby, Rails, database, and queue versions are actually deployed?
- Does the change rely on a default that differs across Rails versions or adapters?
- Are upgrade-only recommendations separated from correctness or security findings?

---

## Ruby Semantics and API Contracts

### Remember Ruby Truthiness

Only `false` and `nil` are falsey. Values such as `0`, `""`, and `[]` are truthy, so code translated from other languages can silently choose the wrong branch.

```ruby
# Bad: zero is truthy, so this does not test whether any rows were found.
if relation.count
  publish_report
end

# Good: state the condition directly and let the database answer efficiently.
publish_report if relation.exists?
```

Review questions:
- Does a condition rely on `0`, an empty string, or an empty collection being falsey?
- Would `empty?`, `any?`, `exists?`, `present?`, or an explicit comparison communicate the intent?
- Is a database relation being loaded only to test whether a row exists?

### Preserve Predicate and Comparison Contracts

Predicate methods should normally end in `?` and return a boolean. Review custom equality carefully: `==`, `eql?`, `equal?`, and `hash` have different contracts.

```ruby
class Money
  attr_reader :amount, :currency

  def initialize(amount, currency)
    @amount = amount
    @currency = currency
  end

  def ==(other)
    other.is_a?(Money) &&
      amount == other.amount &&
      currency == other.currency
  end

  alias eql? ==

  def hash
    [amount, currency].hash
  end
end
```

Review questions:
- If `eql?` is overridden, is `hash` consistent so Hash and Set lookups work?
- Is `equal?` being used accidentally where value equality is intended?
- Does a predicate return a domain object or `nil` when callers expect `true` or `false`?

### Keep Keyword Arguments Explicit

Ruby separates positional and keyword arguments. Broad `**options` parameters can hide typos and weaken public API contracts.

```ruby
# Bad: silently accepts misspelled or unsupported options.
def charge(customer, **options)
  gateway.charge(customer, options)
end

# Good: required and optional keywords are visible to callers.
def charge(customer, amount:, currency: "USD", idempotency_key:)
  gateway.charge(
    customer,
    amount: amount,
    currency: currency,
    idempotency_key: idempotency_key
  )
end
```

Use `...` for transparent delegation only when forwarding every positional argument, keyword argument, and block is intentional.

Review questions:
- Are required keywords declared without defaults?
- Does a wrapper preserve keywords and blocks correctly?
- Would accepting arbitrary keywords turn a caller typo into delayed or silent behavior?

### Keep Metaprogramming Boundaries Small

Ruby makes dynamic APIs easy to build, but reviewers should treat `eval`, `class_eval` with strings, `send`, `const_get`, and dynamic constantization as trust boundaries.

```ruby
# Bad: user input controls the method that is invoked.
account.send(params[:operation])

# Good: map external input to a fixed internal operation.
OPERATIONS = {
  "activate" => :activate!,
  "suspend" => :suspend!
}.freeze

operation = OPERATIONS.fetch(params[:operation])
account.public_send(operation)
```

Review questions:
- Can external input select a method, class, constant, template, or code string?
- Is a fixed allowlist used before `public_send` or `constantize`?
- Is metaprogramming isolated and covered by contract tests?

### Treat Deserialization and Shell Execution as Trust Boundaries

`Marshal.load` can instantiate Ruby objects and must not receive untrusted bytes. Prefer data-only formats such as JSON, and use `YAML.safe_load` or `Psych.safe_load` with an explicit allowlist when YAML is required. Build process arguments as separate values instead of interpolating a shell command.

```ruby
# Bad: untrusted input can trigger unsafe object deserialization.
payload = Marshal.load(request.raw_post)

# Good: parse data-only JSON values, then validate their shape.
payload = JSON.parse(request.raw_post)

# Good: permit only the YAML types and aliases the format requires.
payload = YAML.safe_load(request.raw_post, permitted_classes: [], aliases: false)

# Bad: a filename can inject additional shell syntax.
system("convert #{uploaded_path} output.png")

# Better: argv form bypasses shell parsing, but not path validation.
system("convert", uploaded_path, "output.png")
```

Review questions:
- Can request, cache, cookie, queue, or file data reach `Marshal.load`, `YAML.load`, or unrestricted `Psych.load`?
- Is parsed data validated before it selects a class, method, path, or database operation?
- Are `permitted_classes` and `aliases` as restrictive as the YAML contract allows?
- Are subprocess arguments passed separately, with the path constrained to the intended upload root and exit status/timeouts handled?

---

## Collections, Mutation, and Nil

### Avoid Shared Collection Defaults

`Hash.new(object)` reuses the same object for every missing key. Use a block when each key needs independent mutable state.

```ruby
# Bad: all missing keys share one array.
grouped = Hash.new([])
grouped[:paid] << 1
grouped[:failed] << 2
# The keys were never assigned; both reads mutated the same hidden default.
grouped # => {}
grouped[:paid] # => [1, 2]
grouped[:failed] # => [1, 2]

# Bad: every element refers to the same array.
matrix = Array.new(3, [])

# Good: the block creates an independent array for each element.
matrix = Array.new(3) { [] }

# Good: each missing key receives its own array.
grouped = Hash.new { |hash, key| hash[key] = [] }
grouped[:paid] << 1
grouped[:failed] << 2
```

Review questions:
- Does a Hash default contain a mutable Array, Hash, or String?
- Is the default block storing the generated value back into the hash when that is intended?
- Could a shared constant or class attribute be mutated across requests or tests?

### Treat Bang Methods as Semantic Signals, Not Guarantees

Ruby's `!` convention usually means a more dangerous or mutating counterpart, but it does not universally mean "raises on failure." Many mutating methods return `nil` when no change was made.

```ruby
name = "ready"

# Bad: `downcase!` returns nil when the string is already lowercase.
normalized = name.downcase!

# Good: use the non-bang form when the return value is the result.
normalized = name.downcase
```

Review questions:
- Is code relying on a bang method's return value without checking its contract?
- Is in-place mutation visible to every owner of the object?
- Would a non-mutating transformation make the data flow clearer?

### Do Not Use Safe Navigation to Hide Broken Invariants

`&.` is useful for genuinely optional relationships. Repeated safe navigation can also turn missing required data into a late `nil` and hide the source of an invalid state.

```ruby
# Bad when every order must have a customer and email.
recipient = order&.customer&.email

# Good: enforce required associations and fail close to the invalid state.
recipient = order.customer.email
```

Review questions:
- Is nil part of the domain, or is it evidence of a broken invariant?
- Should the model, database, or caller guarantee presence instead?
- Does `dig` or `&.` make an error disappear only for it to fail later?

### Choose the Enumerable Operation That Matches the Intent

Use `each` for side effects, `map` for transformation, `filter_map` for transform-and-compact, and `each_with_object` for accumulation. Avoid chains that allocate intermediate arrays in hot paths.

```ruby
# Bad: uses map for side effects and leaves an unused array behind.
orders.map { |order| AuditLog.write(order) }

# Good: side effect is explicit.
orders.each { |order| AuditLog.write(order) }

# Good: transform and discard nil values in one pass.
emails = users.filter_map { |user| user.email if user.subscribed? }
```

Review questions:
- Is `map` used when its returned collection is ignored?
- Does a long chain allocate large intermediate collections?
- Is a relation converted to an Array before the database has applied filtering, ordering, or aggregation?

---

## Exceptions and Resource Safety

### Rescue the Smallest Expected Failure

A bare `rescue` catches `StandardError` and its subclasses. It still combines many unrelated failures, including programming errors, database errors, timeouts, and validation errors.

```ruby
# Bad: converts every ordinary application failure into the same response.
def create
  order = Orders::Create.call(order_params)
  render json: order
rescue => error
  Rails.logger.info(error.message)
  render json: { error: error.message }, status: :internal_server_error
end

# Good: translate expected errors at the boundary and let unexpected errors
# reach centralized reporting.
rescue_from Orders::InvalidOrder, with: :render_invalid_order

def create
  order = Orders::Create.call(order_params)
  render json: { id: order.id, status: order.status }, status: :created
end
```

Review questions:
- Is the rescued exception expected at this boundary?
- Is the protected block narrow enough to avoid catching unrelated bugs?
- Does the response expose an internal exception message, SQL, path, token, or vendor detail?

### Preserve the Original Backtrace and Cause

Use bare `raise` to re-raise the current exception. `raise error` also re-raises the same exception object and preserves its existing backtrace, but bare `raise` makes that intent clearer. When translating to a domain error, report the original exception object and keep its cause chain.

```ruby
begin
  gateway.charge(payload)
rescue Gateway::Timeout => error
  Rails.error.report(error, context: { order_id: order.id })
  raise Payments::Unavailable, "payment gateway timed out"
end
```

Inside a `rescue` block, raising a new exception keeps the rescued exception as its implicit `cause`. Constructing a new exception, such as `raise Payments::Unavailable, error.message`, creates a new backtrace; do that only when the boundary needs a domain-specific error.

See [Error Handling Guide](cross-cutting/error-handling-principles.md) for boundary, cause-chain, and reporting principles shared across ecosystems.

Review questions:
- Is structured context logged without secrets or full payment data?
- Does the error retain a useful cause chain?
- Is the log level appropriate, and will the error be reported exactly once?

### Use Blocks or Ensure for Cleanup

Prefer block-based resource APIs because they close resources even when an exception is raised. Use `ensure` when no block form exists.

```ruby
# Good: File.open closes the handle after the block.
File.open(path, "rb") do |file|
  checksum(file)
end

connection = pool.checkout
begin
  consume(connection)
ensure
  pool.checkin(connection)
end
```

Review questions:
- Are files, locks, temporary directories, and checked-out resources released on every path?
- Does an `ensure` block accidentally `return` and suppress an exception?
- Is retry logic bounded and limited to transient failures?

---

## Rails Controllers and Security

### Require and Permit Parameters Explicitly

Rails 8 provides `params.expect` to require the expected shape and allow only named attributes. For older supported Rails versions, follow the established `require(...).permit(...)` convention.

```ruby
# Bad: unfiltered controller parameters at a mass-assignment boundary.
Order.create!(params[:order])

# Bad: permits current and future attributes, including sensitive columns.
params.expect(order: {})

# Good: allowlist the flat request contract.
def order_params
  params.expect(order: [:product_id, :quantity, :shipping_address_id])
end

# Bad: a single array does not express an array of nested parameter hashes.
params.expect(order: [:product_id, line_items_attributes: [:id, :sku, :quantity]])

# Good: use the double-array form for nested resource arrays.
params.expect(order: [
  :product_id,
  line_items_attributes: [[:id, :sku, :quantity]]
])
```

Review questions:
- Are authorization-sensitive fields such as `user_id`, `role`, `paid`, or `admin` excluded?
- Do nested resource arrays use the `[[...]]` form, rather than treating them as a flat nested hash?
- Are nested hashes and arrays permitted with the exact expected shape?
- Is `permit!`, `to_unsafe_h`, or an empty hash permission widening the contract?

### Parameterize Active Record Queries

Never interpolate request data into SQL fragments. Prefer hash conditions or placeholders, and allowlist dynamic identifiers such as sort columns.

```ruby
# Bad: SQL injection.
Order.where("status = '#{params[:status]}'")

# Good: hash conditions are parameterized.
Order.where(status: params[:status])

# Good: placeholders for non-equality predicates.
Order.where("total_cents >= ?", params[:minimum_cents])

# Bad: values are quoted, but the column name is still attacker-controlled.
Order.order(Arel.sql("#{params[:sort]} DESC"))

# Good: map external values to fixed SQL identifiers.
SORTS = {
  "newest" => { created_at: :desc },
  "total" => { total_cents: :desc }
}.freeze

Order.order(SORTS.fetch(params[:sort], SORTS.fetch("newest")))
```

Review questions:
- Does user input reach `where`, `order`, `select`, `joins`, `having`, or `find_by_sql` as a string?
- Is `Arel.sql` used only for a developer-controlled literal?
- Are dynamic columns and directions selected from an allowlist?

See [SQL Injection Guide](cross-cutting/sql-injection-prevention.md) for parameterization and dynamic-identifier patterns across ORMs.

### Keep Rendering and Redirects on an Allowlist

Rendering an Active Record object directly can expose newly added columns without a controller change. Use a serializer or explicit field list. Treat redirects, file paths, and HTML safety overrides as security boundaries.

```ruby
# Bad: future columns can become part of the API response.
render json: order

# Good: response fields are intentional and versionable.
render json: {
  id: order.id,
  status: order.status,
  total_cents: order.total_cents
}, status: :created

# Bad: open redirect when a user controls the destination.
redirect_to params[:return_to], allow_other_host: true

# Good: redirect to an application route.
redirect_to order_path(order)
```

Review questions:
- Are secrets, password digests, tokens, internal notes, or personal data serialized?
- Does `html_safe`, `raw`, or `safe_join` receive untrusted content?
- Can user input control an external redirect, file download path, or response header?

### Keep Authentication, Authorization, and Scoping Separate

Authentication establishes who the caller is; authorization decides what that caller may do. Loading a record by global ID before authorization can create an insecure direct object reference.

```ruby
# Bad: any authenticated user may be able to load another user's order.
order = Order.find(params[:id])

# Good: scope the lookup through the authorized owner or policy scope.
order = current_user.orders.find(params[:id])
```

Review questions:
- Is every member action authorized, including newly added controller actions?
- Is the record lookup scoped before update, destroy, download, or enqueue?
- For browser sessions, are state-changing requests protected against CSRF?

### Protect Session-Backed Browser Requests

CSRF protection is required when a browser automatically sends an authenticated session cookie. API-only endpoints that use an explicit bearer token can use a different strategy, but disabling CSRF protection is not safe merely because an endpoint returns JSON.

```ruby
# Good: session-backed controllers keep forgery protection enabled.
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end
```

```ruby
# Good: configure the session store in an initializer (for example
# config/initializers/session_store.rb), not inside a controller class.
# Keep cookies unavailable to JavaScript, HTTPS-only in production, and make
# the cross-site policy explicit for the application's flows.
Rails.application.config.session_store :cookie_store,
  key: "_app_session",
  secure: Rails.env.production?,
  httponly: true,
  same_site: :lax
```

Review questions:
- Does any browser-authenticated `POST`, `PATCH`, `PUT`, or `DELETE` skip `protect_from_forgery`?
- Are `secure`, `httponly`, and `same_site` cookie settings appropriate for the deployment and login flows?
- Does an API-only endpoint avoid cookie authentication, or otherwise use a deliberate CSRF defense?

### Review Active Storage and Server-Side Fetches

For Active Storage uploads and any server-side URL fetch, verify blob ownership, content-type and size validation, and SSRF controls before accepting a user-controlled URL. Signed/expiring URLs, direct-upload limits, and variant parameters should stay under an allowlist. See the [Security Review Guide](security-review-guide.md) for broader request and asset review guidance.

Review questions:
- Can an attachment download, redirect, or server-side fetch access a file or URL outside the authorized scope?
- Are content type, size, and ownership checked before persisting or transforming a blob?
- Does a user-controlled URL used for server-side fetching enforce host allowlists and block private network ranges?

### Make Retried Write Requests Idempotent

A client or proxy can retry a request after the database commits but before it receives the response. For operations such as order creation, require a caller-supplied idempotency key, scope it to the authenticated principal and operation, and enforce uniqueness in the database.

```ruby
# The service stores both the key and a fingerprint of the validated request.
order = Orders::CreateOnce.call(
  actor: current_user,
  idempotency_key: request.headers.fetch("Idempotency-Key"),
  attributes: order_params
)

# Migration: require the key when this API requires the header, then close
# concurrent duplicate-create races. On an existing populated table, backfill
# or supply a temporary default before adding `null: false`.
add_column :orders, :idempotency_key, :string, null: false
add_index :orders, [:user_id, :idempotency_key], unique: true
```

When the same key is reused, return the original result only if the request fingerprint matches. Reject key reuse with different attributes instead of silently returning or mutating the wrong resource.

Review questions:
- Can a timeout or enqueue failure happen after the write commits?
- Will a caller retry create, payment, invitation, or other non-idempotent work?
- Is the required key rejected before insert and stored in a `null: false` column? A unique index permits multiple `NULL` values on many adapters.
- For existing tables, does the migration backfill values before enforcing `null: false`?
- Is idempotency enforced by a unique constraint and tested under concurrent requests?

---

## Active Record Correctness

### Pair Model Validation With Database Constraints

Model validations improve error messages but do not protect against concurrent writers or non-Rails clients. Important invariants need database constraints and indexes.

```ruby
class Membership < ApplicationRecord
  validates :user_id, uniqueness: { scope: :team_id }
end

# Migration also required:
add_index :memberships, [:team_id, :user_id], unique: true
add_check_constraint :orders, "total_cents >= 0", name: "orders_total_nonnegative"
```

Review questions:
- Do uniqueness, non-null, foreign-key, and range invariants exist in the database?
- Does application code handle the constraint violation from a concurrent request?
- Is a new query pattern backed by an appropriate index?

### Know Which APIs Skip Validations and Callbacks

Bulk methods are valuable, but methods such as `update_all`, `delete_all`, `insert_all`, and direct SQL bypass parts of the ordinary model lifecycle.

```ruby
# This does not run model validations or update callbacks.
Order.where(expired: true).update_all(status: "cancelled", updated_at: Time.current)
```

Review questions:
- Is skipping validations, callbacks, timestamps, auditing, and dependent behavior intentional?
- Would `destroy_all` be required for dependent cleanup, despite being slower?
- Could a bulk write bypass a counter-cache callback and require `reset_counters` or another explicit reconciliation step?
- Are bulk operations bounded, observable, and safe to retry?

### Keep Callbacks Small and Predictable

Callbacks that send emails, call APIs, enqueue multiple workflows, or mutate unrelated models make persistence hard to reason about.

Prefer explicit application services for orchestration. If work must happen only after a transaction commits, use `after_commit` or enqueue-after-commit behavior deliberately.

Review questions:
- Can saving a model unexpectedly trigger network I/O or a large cascade?
- Could a callback run during tests, data migrations, console scripts, or retries?
- Is callback ordering part of an undocumented correctness dependency?

### Treat Enum and Scope Changes as Data Contract Changes

Integer-backed enums depend on stable ordinal mappings. Append new values or use explicit mappings; do not reorder existing entries.

```ruby
# Safer for long-lived data and cross-service contracts.
enum :status, {
  pending: 0,
  paid: 1,
  cancelled: 2
}
```

Scopes should return relations consistently. A conditional scope that returns `nil` or an Array breaks composability.

Review questions:
- Does an enum change reinterpret existing rows?
- Does a scope remain chainable for every input?
- Is a `default_scope` hiding records or ordering in surprising contexts?

### Keep Counter Caches and Query Caches Correct

Counter caches are denormalized data maintained by callbacks. Bulk writes, direct SQL, imports, and deleted rows that bypass the normal lifecycle can make them drift; repair deliberately with `reset_counters` after verifying the source-of-truth query.

Long-running jobs should also avoid assuming a query result remains current for the whole job. Check the query-cache scope and use an uncached block or a fresh query when later steps must observe writes or concurrent changes.

Review questions:
- Can `update_all`, `delete_all`, imports, or direct SQL bypass a counter-cache update?
- Is a counter-cache repair observable and based on the current source of truth?
- Could a cached query result become stale across phases of a long-running job?

---

## Query Performance

### Detect and Prevent N+1 Queries

Association access inside a loop is a review hotspot. Choose eager-loading behavior based on whether the association is only loaded or also used in SQL conditions.

```ruby
# Bad: one query for orders, then one query per customer.
orders = Order.where(status: "paid")
orders.each { |order| puts order.customer.name }

# Good: usually two queries, with predictable object loading.
orders = Order.where(status: "paid").preload(:customer)

# Good when Rails should select an eager-loading strategy for access.
orders = Order.includes(:customer).where(status: "paid")

# Use eager_load when a LEFT OUTER JOIN is intentionally required.
orders = Order.eager_load(:customer).where(customers: { active: true })
```

`strict_loading` can turn accidental lazy loads into visible failures in development or tests.

`eager_load` uses a `LEFT OUTER JOIN`. It can change result cardinality when it joins a collection association: a parent may appear once per matching child. Use `distinct`, a subquery, or separate the filtering query from `preload` when the caller needs one parent row per record.

See [N+1 Queries Guide](cross-cutting/n-plus-one-queries.md) for cross-framework detection and loading strategies.

Review questions:
- Does a serializer, view, GraphQL resolver, or job walk unloaded associations?
- Is the chosen eager-loading method compatible with filtering, ordering, and result cardinality?
- Could a collection join duplicate parent rows or require `distinct`, a subquery, or a separate `preload` step?
- Are query-count assertions or strict loading protecting important endpoints?

### Keep Filtering and Aggregation in the Database

Loading records before filtering wastes memory and can change semantics.

```ruby
# Bad: loads every paid order and filters in Ruby.
large_orders = Order.paid.to_a.select { |order| order.total_cents >= 10_000 }

# Good: database applies the predicate.
large_orders = Order.paid.where(total_cents: 10_000..)

# Bad: instantiates records just to read one column.
emails = User.active.map(&:email)

# Good: reads only the requested column.
emails = User.active.pluck(:email)
```

Review questions:
- Is `to_a`, `map`, `select`, or `sort_by` forcing work into Ruby too early?
- Would `pluck`, `pick`, `ids`, `exists?`, `count`, `sum`, or `maximum` avoid model instantiation?
- Does the selected column, SQL expression, adapter, or custom attribute type preserve the value type the caller expects?
- Does the query select more columns or rows than the caller needs?

### Batch Large Data Sets and Paginate Endpoints

Use `find_each` or `in_batches` for large background processing, and use stable pagination for list endpoints.

```ruby
Order.where(status: "pending").find_each(batch_size: 1_000) do |order|
  Reconciliation.check(order)
end
```

`find_each` and `in_batches` batch by a cursor (the primary key by default) and can ignore or replace a relation's custom `ORDER BY`. Use an explicit cursor/order supported by the current Rails version, or a dedicated query, when business ordering matters.

Review questions:
- Can this query grow without a bound?
- Is batch processing compatible with its cursor, ordering, and mutation behavior?
- Does pagination use a deterministic order and an indexed cursor or key?

### Review Caching With Invalidation in Mind

Caching can hide N+1 queries while introducing stale or cross-tenant data. Cache keys must include every input that changes the result.

Review questions:
- Does the key include tenant, locale, authorization scope, and versioned data?
- Is invalidation tied to the records that affect the cached value?
- Could sensitive data be served to another user or tenant?

---

## Transactions and Concurrency

### Keep Transactions Focused on Database State

Database transactions do not roll back HTTP calls, messages already delivered to an external broker, files, or payments.

```ruby
# Bad: payment can succeed even if the database transaction rolls back.
Order.transaction do
  gateway.charge(order.total_cents)
  order.update!(status: "paid")
end

# Better: configure this job to enqueue only after commit, then persist an
# explicit transition and reconcile the idempotent external operation.
class PaymentJob < ApplicationJob
  self.enqueue_after_transaction_commit = true
end

Order.transaction do
  order.update!(status: "payment_pending")
  PaymentJob.perform_later(order)
end
```

Do not rely on a version-dependent enqueue default. Rails 8.0/8.1 applications and queue adapters can enqueue immediately depending on `config.load_defaults` and deployment topology; newer Rails defaults may defer more often, but the job should declare the behavior it requires. If the enqueue itself must be durable with the state change, use an outbox or a reconciliation path.

Review questions:
- Which side effects are actually covered by the transaction?
- Does the exact job class declare post-commit enqueue behavior, rather than relying on an adapter or Rails-version default?
- Could a timeout mean "failed" or "succeeded but the response was lost"?
- Is there a recovery or reconciliation path for partial completion?

### Do Not Swallow Database Errors Inside a Broken Transaction

Some adapters, notably PostgreSQL, leave a transaction unusable after a statement error until it is rolled back. Catch expected constraint errors outside the transaction boundary or restart the whole transaction deliberately.

Review questions:
- Is `ActiveRecord::StatementInvalid` rescued inside a transaction and then followed by more SQL?
- Is retry limited to known transient conflicts such as deadlocks or serialization failures?
- Does retry repeat an external side effect?

### Lock the Invariant, Not Just the Code Path

Ruby process locks do not protect data across multiple processes or hosts. Use unique constraints, atomic updates, optimistic locking, or row locks for shared database invariants.

```ruby
order.with_lock do
  return if order.paid?

  order.update!(status: "payment_pending")
end
```

Review questions:
- Can two requests observe the same old state and both proceed?
- Would an atomic conditional update or unique index be simpler than a lock?
- Is lock ordering consistent to avoid deadlocks?

### Choose Optimistic or Pessimistic Locking Deliberately

Use optimistic locking for ordinary edits where conflicts are uncommon and the caller can reload or resolve a conflict. Use a short pessimistic lock such as `with_lock` for a small critical state transition that needs serialized access.

```ruby
# Migration: Rails increments this column and rejects stale updates.
add_column :orders, :lock_version, :integer, default: 0, null: false

begin
  order.update!(shipping_address: new_address)
rescue ActiveRecord::StaleObjectError
  # Reload, return a conflict response, or ask the user to reconcile changes.
end
```

Review questions:
- Can a low-contention user edit use `lock_version` and a conflict response instead of holding a row lock?
- Does pessimistic locking cover only the minimal state transition and preserve a consistent lock order?

### Treat Mutable Global State as Concurrent State

Class variables, class instance variables, constants containing mutable objects, memoization, and singleton clients may be shared by request threads.

Review questions:
- Is lazy initialization thread-safe and safe during code reload?
- Is request-specific data stored in a global, class variable, or long-lived thread local?
- Are shared clients documented as thread-safe by their library?

---

## Active Job and External Side Effects

### Make Retried Jobs Idempotent

Jobs may be retried when configured by Active Job or the queue backend. A process can also stop after an external side effect succeeds but before local state is updated.

```ruby
class CapturePaymentJob < ApplicationJob
  self.enqueue_after_transaction_commit = true
  retry_on PaymentGateway::Timeout, wait: :polynomially_longer, attempts: 5

  def perform(order)
    order.with_lock do
      return if order.paid?
      order.update!(status: "payment_processing")
    end

    result = PaymentGateway.capture(
      amount: order.total_cents,
      idempotency_key: "order-#{order.id}-capture"
    )

    order.update!(status: "paid", payment_reference: result.reference)
  end
end
```

The gateway idempotency key, persisted state, and reconciliation process must work together. A database flag alone cannot prove that an external charge did not already happen.

Review questions:
- What happens if the worker stops after the side effect but before the final update?
- Is the idempotency key stable across retries but unique to the intended operation?
- Are retryable and permanent failures handled differently?
- Which states are terminal, retryable, or recoverable, and how does a stuck `payment_processing` state become visible for reconciliation?

### Understand GlobalID Arguments

Active Job can serialize Active Record objects with GlobalID. The job loads the record at execution time, not enqueue time. If the record has been deleted, deserialization raises `ActiveJob::DeserializationError` before `perform` runs.

When absence is an expected business case, pass an ID and handle `ActiveRecord::RecordNotFound` narrowly inside the job. Do not use a blanket `discard_on ActiveJob::DeserializationError` unless every deserialization failure is intentionally disposable; it can also hide serializer or deployment problems.

Review questions:
- Is the job intentionally using current record state rather than a snapshot?
- What should happen when the record is deleted or no longer eligible?
- Does `discard_on ActiveJob::DeserializationError` lose work that should be investigated instead?

### Enqueue With Transaction Boundaries Deliberately

Jobs that can run before their records commit may fail to find those records. Rails supports enqueue-after-commit behavior, but transactional guarantees depend on the exact job setting, queue adapter, Rails load defaults, and database topology.

Review questions:
- Can the worker run before the creating transaction commits?
- Does the code accidentally rely on the job table sharing the application database?
- If enqueue fails after data commits, is there an outbox, retry, or reconciliation path?

### Put Timeouts and Observability Around Network Work

Every external call needs bounded connect/read/write timeouts, structured error reporting, and enough identifiers to trace a retry without logging secrets.

Review questions:
- Are timeouts explicit in the client configuration?
- Are queue latency, attempts, external request IDs, and final outcomes observable?
- Is a long-running job split into resumable or checkpointed units when appropriate?

---

## Testing and Tooling

### Test Behavior at the Right Boundary

Use model tests for domain rules, request/system tests for controller behavior, and job tests for serialization, retry, and side-effect boundaries. Avoid tests that only assert a callback or private method was invoked.

High-value cases include:
- unpermitted parameters cannot update protected attributes;
- unsafe sort/filter input cannot alter SQL structure;
- authorization scopes records before lookup;
- serializers do not expose sensitive columns;
- N+1 regressions fail through query-count assertions or strict loading;
- jobs are safe when performed twice;
- deleted GlobalID records and permanent gateway failures are handled intentionally;
- a timeout after a successful external side effect is reconciled without duplication.

### Keep Time and Asynchronous Tests Deterministic

Use Rails time helpers instead of real sleeps. Run jobs through the test adapter or a backend-specific integration test, and assert both enqueue behavior and performed behavior where each matters.

```ruby
travel_to(Time.zone.local(2026, 7, 14, 10, 0, 0)) do
  assert_enqueued_with(job: ExpireOrderJob, at: 30.minutes.from_now) do
    order.schedule_expiration!
  end
end
```

Review questions:
- Does a test depend on wall-clock timing, global order, or previously created data?
- Are external services replaced at a clear adapter boundary?
- Do parallel tests share mutable constants, files, ports, or non-transactional state?

### Run the Checks the Project Actually Configures

Common commands include:

```bash
bundle exec ruby -wc path/to/file.rb
bundle exec rubocop
bundle exec brakeman -q
bundle exec rails test
bundle exec rspec
```

Run only tools present in the repository, and inspect their configuration before treating style or complexity thresholds as universal rules. Security findings from Brakeman and dependency scanners require human validation, not blind suppression.

---

## Review Checklist

### Ruby Semantics
- [ ] Conditions account for Ruby truthiness (`0`, `""`, and `[]` are truthy).
- [ ] Equality and `hash` contracts are consistent.
- [ ] Keyword arguments and forwarding preserve the intended API contract.
- [ ] Dynamic method or constant lookup is allowlisted.
- [ ] Mutable Hash/Array defaults, constants, and class state are not shared accidentally.
- [ ] Untrusted data never reaches unsafe deserialization or interpolated shell commands.
- [ ] Bang-method and safe-navigation return semantics are understood.

### Exceptions and Resources
- [ ] Rescue clauses handle specific expected failures at narrow boundaries.
- [ ] Unexpected errors retain their cause and backtrace.
- [ ] Client responses do not expose internal exception messages.
- [ ] Logs include safe structured context and the exception object.
- [ ] Resources and locks are released on every path.
- [ ] Retries are bounded and cannot duplicate non-idempotent work.

### Controllers and Security
- [ ] Strong parameters use an exact allowlist; no `permit!` or unsafe hash conversion.
- [ ] Nested resource arrays use `params.expect(...: [[...]])` with the intended shape.
- [ ] SQL values are parameterized and dynamic identifiers are allowlisted.
- [ ] Authentication, authorization, and record scoping are all present.
- [ ] An unscoped `Model.find(params[:id])` cannot bypass ownership or policy checks.
- [ ] Retried write requests use scoped idempotency keys and database uniqueness where required.
- [ ] Serialized fields are explicit and exclude sensitive data.
- [ ] Redirects, HTML safety overrides, files, and headers do not trust user input or permit open redirects.
- [ ] State-changing browser requests have CSRF protection, and session cookies use intentional `secure`, `httponly`, and `same_site` settings.
- [ ] Active Storage uploads and server-side URL fetches validate ownership, content, and SSRF boundaries.

### Active Record
- [ ] Critical model validations are backed by database constraints and indexes.
- [ ] Bulk APIs intentionally account for skipped callbacks, validations, and timestamps.
- [ ] Bulk writes cannot silently drift counter caches; repair and reconciliation are explicit.
- [ ] Callbacks are small and do not hide orchestration or network side effects.
- [ ] Enum mappings preserve existing persisted values.
- [ ] Scopes remain relations and compose for every input.
- [ ] Concurrency invariants use constraints, atomic updates, optimistic locking, or short database locks.

### Queries and Performance
- [ ] Association access in loops is preloaded or explicitly justified.
- [ ] `includes`, `preload`, or `eager_load` matches the query semantics.
- [ ] Collection joins cannot duplicate parent rows or change cardinality unnoticed.
- [ ] Filtering, sorting, aggregation, and existence checks stay in the database.
- [ ] Large data sets use batches; list endpoints are paginated with stable ordering.
- [ ] New filter/join/order patterns have supporting indexes.
- [ ] Cache keys include tenant, authorization, locale, and data versions as needed.

### Jobs and External Services
- [ ] Jobs are safe under retry, duplicate delivery, and worker interruption.
- [ ] External operations use stable idempotency keys where supported.
- [ ] GlobalID deletion and stale/current-state semantics are intentional; expected absence is handled narrowly.
- [ ] Enqueue timing is declared on the job and does not rely accidentally on queue/database topology or version defaults.
- [ ] Partial completion has reconciliation, compensation, or an outbox path.
- [ ] Terminal, retryable, and stuck processing states are observable and recoverable.
- [ ] Network calls have timeouts, observability, and secret-safe logging.

### Tests and Automation
- [ ] Request tests cover parameter filtering, authorization, status codes, and response fields.
- [ ] Query-count or strict-loading tests protect performance-sensitive paths.
- [ ] Job tests cover retries, duplicate execution, deletion, and partial failure.
- [ ] Time-dependent tests use deterministic Rails time helpers.
- [ ] The repository's configured Ruby, Rails, lint, test, and security checks pass.

---

## References

- [Ruby Releases](https://www.ruby-lang.org/en/downloads/releases/)
- [Ruby Syntax: Methods and Arguments](https://ruby-doc.org/3.4/syntax/methods_rdoc.html)
- [Ruby Syntax: Exceptions](https://ruby-doc.org/3.4/syntax/exceptions_rdoc.html)
- [Rails Action Controller Overview](https://guides.rubyonrails.org/action_controller_overview.html)
- [Rails Active Record Query Interface](https://guides.rubyonrails.org/active_record_querying.html)
- [Rails Active Record Transactions](https://api.rubyonrails.org/classes/ActiveRecord/Transactions/ClassMethods.html)
- [Rails Active Job Basics](https://guides.rubyonrails.org/active_job_basics.html)
- [Securing Rails Applications](https://guides.rubyonrails.org/security.html)
- [Testing Rails Applications](https://guides.rubyonrails.org/testing.html)
- [RuboCop Documentation](https://docs.rubocop.org/rubocop/)
- [RuboCop Rails Documentation](https://docs.rubocop.org/rubocop-rails/)
- [Brakeman](https://brakemanscanner.org/)
