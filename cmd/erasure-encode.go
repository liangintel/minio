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

/*
#cgo CFLAGS: -I/opt/stack/qat/quickassist/lookaside/access_layer/src/sample_code/functional/sym/qat_hash
#cgo LDFLAGS:  -lssl -lcrypto -lqat_hash -L/opt/stack/qat/quickassist/lookaside/access_layer/src/sample_code/functional/sym/qat_hash
#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h> //may need to install `apt install libssl-dev`
#include "qat_hash.h"

*/
import "C"

import (
	"context"
	"io"

	"sync"
	//"reflect"
	"unsafe"
	//"fmt"
	//"sync/atomic"
	//"time"
	golog "log"

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

const PIECE_NUM = 32
const PIECE_SIZE = (4*1024*1024)
var g_request_cnt int32 = 0
// Encode reads from the reader, erasure-encodes the data and writes to the writers.
func (e *Erasure) Encode(ctx context.Context, src io.Reader, writers []io.Writer, buf_ori []byte, quorum int) (total int64, err error) {
	writer := &parallelWriter{
		writers:     writers,
		writeQuorum: quorum,
		errs:        make([]error, len(writers)),
	}

	// version check
	max_object_size := int(C.get_max_object_size()) * (1024*1024)
	piece_size := int(C.get_cont_piece_size())
	piece_num := max_object_size / piece_size
	if(piece_num != PIECE_NUM) {
		golog.Println("Failure: piece_num mismatch!")
	}

	eng_i := -1
	buf := buf_ori[:]
	var buff_arr *[PIECE_NUM]uintptr
	buf_i := 0
	r, ok := src.(*hash.Reader)
    if ok {
		eng_i = r.GetQATEng()	//engine will be released in r.MD5Sum()
	}
	
	if(eng_i >= 0) {
		buff_arr_ := C.get_engine_buffs(C.int(eng_i))
		buff_arr = (*[PIECE_NUM]uintptr)(buff_arr_)
	}
/*
	defer func() {
		if(eng_i >= 0) {
			//release qat engine
			//r.PutQATEng()
		}
	} ()
*/
	for ; ; buf_i++ {
		if(eng_i >= 0) {
			buf_ := (*[PIECE_SIZE]byte)(unsafe.Pointer(buff_arr[buf_i]))
			buf = buf_[:]
		}
		var blocks [][]byte
		n, err := io.ReadFull(src, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			logger.LogIf(ctx, err)
			return 0, err
		}
		eof := err == io.EOF || err == io.ErrUnexpectedEOF
		if(eng_i >= 0) {
			if(eof || (n == 0 && total != 0)) {
				//write data (offset)
				ret := C.md5_write(C.int(eng_i), (*C.uchar)(unsafe.Pointer(&buf[0])), C.int(total+int64(n)), 0);
				if ret != 0 {
					golog.Println("======= md5_write failure =========")
				}
		
				//calculate md5, QAT engine will be released
				r.MD5Sum()
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
		
	return total, nil
}
