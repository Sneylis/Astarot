package Core

import (
	"bufio"
	"context"
	"log"
	"os"
)

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

func SaveResults(ctx context.Context, in <-chan string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer func() {
		if err := writer.Flush(); err != nil {
			log.Println("[WARN] flush error:", err)
		}
	}()

	// Слушаем канал и сигнал контекста
	for {
		select {
		case domain, ok := <-in:
			if !ok {
				// канал закрыт, значит продюсеры закончили — нормальный выход
				return nil
			}
			if _, err := writer.WriteString(domain + "\n"); err != nil {
				return err
			}

		case <-ctx.Done():
			// Контекст отменён — дочитаем всё, что осталось в канале
			for domain := range in {
				if _, err := writer.WriteString(domain + "\n"); err != nil {
					return err
				}
			}
			return ctx.Err() // вернём причину отмены (можно заменить на nil, если не критично)
		}
	}
}
