package set

type Set struct {
	m       map[string]struct{}
	counter int
}

func New() Set {
	return Set{
		m: make(map[string]struct{}),
	}
}

func (s *Set) Add(item string) {
	s.m[item] = struct{}{}
	s.counter++
}

func (s *Set) Remove(item string) {
	delete(s.m, item)
}

func (s *Set) Contains(item string) bool {
	_, ok := s.m[item]
	return ok
}

func (s *Set) Size() int {
	return s.counter
}

func (s Set) String() string {
	result := "{"
	for k := range s.m {
		result += k + ","
	}
	if len(result) > 1 {
		result = result[:len(result)-1]
	}
	result += "}"
	return result
}

func (s *Set) Union(other *Set) Set {
	result := New()
	for k := range s.m {
		result.Add(k)
	}
	for k := range other.m {
		result.Add(k)
	}
	return result
}
