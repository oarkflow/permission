package ds

type Link[A any] interface {
	IsEmpty() bool
	Append(A) Link[A]
	Concat(Link[A]) Link[A]
	AsSlice() []A
}

type emptyLink[A any] struct{}

type appendLink[A any] struct {
	element A
	next    Link[A]
}

type concatLink[A any] struct {
	left, right Link[A]
}

func Empty[A any]() Link[A] {
	return &emptyLink[A]{}
}

func (e *emptyLink[A]) IsEmpty() bool {
	return true
}

func (e *emptyLink[A]) Append(element A) Link[A] {
	return &appendLink[A]{element: element, next: e}
}

func (e *emptyLink[A]) Concat(other Link[A]) Link[A] {
	return other
}

func (e *emptyLink[A]) AsSlice() []A {
	return []A{}
}

func (a *appendLink[A]) IsEmpty() bool {
	return false
}

func (a *appendLink[A]) Append(element A) Link[A] {
	return &appendLink[A]{element: element, next: a}
}

func (a *appendLink[A]) Concat(other Link[A]) Link[A] {
	if other.IsEmpty() {
		return a
	}
	return &concatLink[A]{left: a, right: other}
}

func (a *appendLink[A]) AsSlice() []A {
	slice := a.next.AsSlice()
	return append(slice, a.element)
}

func (c *concatLink[A]) IsEmpty() bool {
	return false
}

func (c *concatLink[A]) Append(element A) Link[A] {
	return &appendLink[A]{element: element, next: c}
}

func (c *concatLink[A]) Concat(other Link[A]) Link[A] {
	if other.IsEmpty() {
		return c
	}
	return &concatLink[A]{left: c, right: other}
}

func (c *concatLink[A]) AsSlice() []A {
	slice := c.left.AsSlice()
	return append(slice, c.right.AsSlice()...)
}
