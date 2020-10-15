/*
 * MinIO Cloud Storage, (C) 2016-2020 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"context"
	"io"

	"sync"

	md5accel "github.com/liangintel/md5accel"
	"github.com/minio/minio/cmd/logger"
	"github.com/minio/minio/pkg/hash"
)

// Writes in parallel to writers
type parallelWriter struct {
	writers     []io.Writer
	writeQuorum int
	errs        []error
}

// Write writes data to writers in parallel.
func (p *parallelWriter) Write(ctx context.Context, blocks [][]byte) error {
	var wg sync.WaitGroup

	for i := range p.writers {
		if p.writers[i] == nil {
			p.errs[i] = errDiskNotFound
			continue
		}

		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, p.errs[i] = p.writers[i].Write(blocks[i])
			if p.errs[i] != nil {
				p.writers[i] = nil
			}
		}(i)
	}
	wg.Wait()

	// If nilCount >= p.writeQuorum, we return nil. This is because HealFile() uses
	// CreateFile with p.writeQuorum=1 to accommodate healing of single disk.
	// i.e if we do no return here in such a case, reduceWriteQuorumErrs() would
	// return a quorum error to HealFile().
	nilCount := 0
	for _, err := range p.errs {
		if err == nil {
			nilCount++
		}
	}
	if nilCount >= p.writeQuorum {
		return nil
	}
	return reduceWriteQuorumErrs(ctx, p.errs, objectOpIgnoredErrs, p.writeQuorum)
}

// Encode reads from the reader, erasure-encodes the data and writes to the writers.
func (e *Erasure) Encode(ctx context.Context, src io.Reader, writers []io.Writer, buf_ori []byte, quorum int) (total int64, err error) {
	writer := &parallelWriter{
		writers:     writers,
		writeQuorum: quorum,
		errs:        make([]error, len(writers)),
	}

	eng := -1					// init the md5 hw engine index to negative value means no hw engine involved
	buf := buf_ori[:]			// later will be changed to hw buf if hw involved
	r, ok := src.(*hash.Reader) // check if it's hash.Reader which contains Md5Hash field
    if ok {
		// try to get the md5 engine, engine will be released in subsequent call MD5Sum()
		eng = md5accel.GetAccelerator(r.Md5Hash)
		md5accel.Set_zero_cpy(r.Md5Hash)
	}

	for {
		if(eng >= 0) {
			// re-use buf from hw, so no memcpy happen between hw and minio, this can increase ~3% throughput
			buf = md5accel.Accel_get_next_buff(r.Md5Hash)
		}
		var blocks [][]byte
		n, err := io.ReadFull(src, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			logger.LogIf(ctx, err)
			return 0, err
		}
		eof := err == io.EOF || err == io.ErrUnexpectedEOF
		if(eng >= 0) {
			if(eof || (n == 0 && total != 0)) {
				// this just tell hw the total length of the object, data itself actually already in hw buf
				md5accel.Accel_write_data(eng, buf, total+int64(n))
		
				// trigger hw to calculate md5 here in a go routing, this will be running parallel with subsequent
				// calls of e.EncodeData and writer.Write. Engine will be released here.
				md5accel.MD5Sum(r.Md5Hash)
			}
		}
		if n == 0 && total != 0 {
			// Reached EOF, nothing more to be done.
			break
		}
		// We take care of the situation where if n == 0 and total == 0 by creating empty data and parity files.
		blocks, err = e.EncodeData(ctx, buf[:n])
		if err != nil {
			logger.LogIf(ctx, err)
			return 0, err
		}
		
		if err = writer.Write(ctx, blocks); err != nil {
			logger.LogIf(ctx, err)
			return 0, err
		}
		total += int64(n)
		if eof {
			break
		}
	}
	if(eng >= 0) {
		// make sure md5 is calculated.
		md5accel.MD5Sum(r.Md5Hash)
	}
	
	return total, nil
}
