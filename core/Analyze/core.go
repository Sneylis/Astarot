package core

func ClearDuplicate(input <-chan string) <-chan string {
	out := make(chan string)

	go func() {
		defer close(out)
		seen := make(map[string]bool)

		for item := range input {
			if !seen[item] {
				seen[item] = true
				out <- item
			}
		}
	}()
	return out
}
