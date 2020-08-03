/*
 * MinIO Cloud Storage, (C) 2017 MinIO, Inc.
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

package hash

/*
#cgo CFLAGS: -I/root/qat/quickassist/lookaside/access_layer/src/sample_code/functional/sym/qat_hash
#cgo LDFLAGS:  -lssl -lcrypto -lqat_hash -L/root/qat/quickassist/lookaside/access_layer/src/sample_code/functional/sym/qat_hash
#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h> //may need to install `apt install libssl-dev`
#include "qat_hash.h"

*/
import "C"

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"fmt"
	"sync"
	"unsafe"
	"reflect"
	"time"
	
//	"github.com/minio/minio/cmd/logger"
//
//	"github.com/minio/minio/pkg/console"
	golog "log"
//	"runtime/debug"

	sha256 "github.com/minio/sha256-simd"
)

var init_once sync.Once
var inited int = 0
var max_engine int = 0
var chan_engines chan int

var sw int = 1
var inflight_engine_num int = 0

// The size of an MD5 checksum in bytes.
const Size = 16


func Init() {
	golog.Println("======= chan_engines Init IN =======")
	max_engine = int(C.get_engine_num())
	chan_engines=make(chan int, max_engine)
	
	r := C.init_qat()
	max_object_size := int(C.get_max_object_size())
	fmt.Println("init_qat:", r, "max_engine:", max_engine, "max_object_size:", max_object_size)
    
	for j:=0;j<max_engine;j++ {
		eng_i := C.get_engine()
		if eng_i < 0 {
		    fmt.Println("failure. index:", j, " eng_i:", eng_i)
		    return;
		}
		chan_engines<-int(eng_i)
	}
	init_threads()
	
	inited = 1
	fmt.Println("inited.")
}

type md5cache struct {
	eng_i int
	blocksize int
	sum_inflight chan int
	digest []byte
}

/*
var bufferPool = &sync.Pool{
        New: func() interface{} {
			m := new(md5cache)
			m.blocksize = 0
			//m.digest = make([]byte, 16)
	        return  m
        },
}
*/

func New() hash.Hash {
	init_once.Do(Init)
	
	//m := bufferPool.Get().(hash.Hash)
	var m hash.Hash = new(md5cache)
	m.Reset()
	return m
}

func (m *md5cache) Size() int { return Size }

func (m *md5cache) Write(data []byte) (nn int, err error) {

	if m.eng_i < 0 {
		inflight_engine_num = inflight_engine_num + 1
		m.eng_i = <-chan_engines
		C.reset_engine(C.int(m.eng_i))
	}
	
	m.blocksize += len(data)
	//fmt.Println("total len:", m.blocksize, "this len: ", len(data))
	r := C.md5_write(C.int(m.eng_i), (*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data)));
	if r != 0 {
		golog.Println("======= md5_write failure =========")
	}
	
	return m.blocksize, nil
}

func (m *md5cache) Sum(data []byte) []byte {
	inflight := <- m.sum_inflight
	//fmt.Println("Sum. ", inflight)

	if(m.digest[0] != 0 || m.digest[1] != 0 || m.digest[2] != 0) {
		//fmt.Println("digest2:", hex.EncodeToString(m.digest))
		m.sum_inflight <- (inflight + 1)
		return m.digest
	}
	
	if m.eng_i < 0 {
		golog.Println("failure. m.eng_i=", m.eng_i, "m.digest=", m.digest, "len(data)=", len(data))
	}

	if len(data) > 0 {
		r := C.md5_write(C.int(m.eng_i), (*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data)));
		if r != 0 {
			golog.Println("======= md5_write2 failure =========")
		}
	}
	
	r2 := C.md5_sum(C.int(m.eng_i), (*C.uchar)(unsafe.Pointer(&m.digest[0])))
	if r2 != 0 {
		golog.Println("======= md5_sum failure =========")
	}
	
	chan_engines <- m.eng_i
	m.eng_i = -1
	inflight_engine_num = inflight_engine_num - 1;
	
	//fmt.Println(m.blocksize, "digest:", hex.EncodeToString(m.digest))
	m.sum_inflight <- (inflight + 1)

	return m.digest
}

func (m *md5cache) Reset() {
	m.blocksize = 0
	m.eng_i = -1
	m.digest = make([]byte, 16)
	m.sum_inflight = make(chan int, 1)
	m.sum_inflight <- 0
}

func (m *md5cache) BlockSize() int {
	return m.blocksize
}


// Reader writes what it reads from an io.Reader to an MD5 and SHA256 hash.Hash.
// Reader verifies that the content of the io.Reader matches the expected checksums.
type Reader struct {
	src        io.Reader
	size       int64
	actualSize int64
	bytesRead  int64

	md5sum, sha256sum   []byte // Byte values of md5sum, sha256sum of client sent values.
	md5Hash, sha256Hash hash.Hash
}

// NewReader returns a new hash Reader which computes the MD5 sum and
// SHA256 sum (if set) of the provided io.Reader at EOF.
func NewReader(src io.Reader, size int64, md5Hex, sha256Hex string, actualSize int64, strictCompat bool) (*Reader, error) {
	if r, ok := src.(*Reader); ok {
		// Merge expectations and return parent.
		return r.merge(size, md5Hex, sha256Hex, actualSize, strictCompat)
	}

	// Create empty reader and merge into that.
	r := Reader{src: src, size: -1, actualSize: -1}
	return r.merge(size, md5Hex, sha256Hex, actualSize, strictCompat)
}

var max_r int = 120
var max_thread int = 120
var chan_r chan *Reader

func init_threads() {
	chan_r = make(chan *Reader, max_r)
	for i:=0; i<max_thread; i++ {
		go func() {
			for {
				r := <- chan_r
				if r.md5Hash != nil {
					//t1 := time.Now().UnixNano()
					r.md5Hash.Sum(nil);
					//t2 := time.Now().UnixNano()
					//td := t2 - t1
					
					//golog.Println("t1:", t1, "t2:", t2, "QAT:", td)
				}
			}
		} ()
	}
}

func (r *Reader) Read(p []byte) (n int, err error) {
	n, err = r.src.Read(p)
	if n > 0 {
		if r.md5Hash != nil {
			r.md5Hash.Write(p[:n])
		}
		if r.sha256Hash != nil {
			r.sha256Hash.Write(p[:n])
		}
	}
	r.bytesRead += int64(n)

	// At io.EOF verify if the checksums are right.
	if err == io.EOF {
		if r.md5Hash != nil {
			tp := reflect.TypeOf(r.md5Hash).String()
			if tp == "*hash.md5cache" {
				chan_r <- r
			}
		}
		
		if cerr := r.verify(); cerr != nil {
			return 0, cerr
		}
	}

	return
}

// Size returns the absolute number of bytes the Reader
// will return during reading. It returns -1 for unlimited
// data.
func (r *Reader) Size() int64 { return r.size }

// ActualSize returns the pre-modified size of the object.
// DecompressedSize - For compressed objects.
func (r *Reader) ActualSize() int64 { return r.actualSize }

// MD5 - returns byte md5 value
func (r *Reader) MD5() []byte {
	return r.md5sum
}

// MD5Current - returns byte md5 value of the current state
// of the md5 hash after reading the incoming content.
// NOTE: Calling this function multiple times might yield
// different results if they are intermixed with Reader.
func (r *Reader) MD5Current() []byte {
	if r.md5Hash != nil {
		return r.md5Hash.Sum(nil)
	}
	return nil
}

// SHA256 - returns byte sha256 value
func (r *Reader) SHA256() []byte {
	return r.sha256sum
}

// MD5HexString returns hex md5 value.
func (r *Reader) MD5HexString() string {
	return hex.EncodeToString(r.md5sum)
}

// MD5Base64String returns base64 encoded MD5sum value.
func (r *Reader) MD5Base64String() string {
	return base64.StdEncoding.EncodeToString(r.md5sum)
}

// SHA256HexString returns hex sha256 value.
func (r *Reader) SHA256HexString() string {
	return hex.EncodeToString(r.sha256sum)
}

// verify verifies if the computed MD5 sum and SHA256 sum are
// equal to the ones specified when creating the Reader.
func (r *Reader) verify() error {
	if r.sha256Hash != nil && len(r.sha256sum) > 0 {
		golog.Println("==sha256==", r.sha256Hash.BlockSize)
		//debug.PrintStack()
		//golog.Println("==1111111==")
		if sum := r.sha256Hash.Sum(nil); !bytes.Equal(r.sha256sum, sum) {
			return SHA256Mismatch{hex.EncodeToString(r.sha256sum), hex.EncodeToString(sum)}
		}
	}
	if r.md5Hash != nil && len(r.md5sum) > 0 {
		golog.Println("==md5==")
		sum := r.md5Hash.Sum(nil);
		if !bytes.Equal(r.md5sum, sum) {
			return BadDigest{hex.EncodeToString(r.md5sum), hex.EncodeToString(sum)}
		}
		golog.Println("calculate sum:", sum, " - input sum:", r.md5sum)
	}
	return nil
}

// merge another hash into this one.
// There cannot be conflicting information given.
func (r *Reader) merge(size int64, md5Hex, sha256Hex string, actualSize int64, strictCompat bool) (*Reader, error) {
	if r.bytesRead > 0 {
		return nil, errors.New("internal error: Already read from hash reader")
	}
	// Merge sizes.
	// If not set before, just add it.
	if r.size < 0 && size >= 0 {
		r.src = io.LimitReader(r.src, size)
		r.size = size
	}
	// If set before and set now they must match.
	if r.size >= 0 && size >= 0 && r.size != size {
		return nil, ErrSizeMismatch{Want: r.size, Got: size}
	}

	if r.actualSize <= 0 && actualSize >= 0 {
		r.actualSize = actualSize
	}

	// Merge SHA256.
	sha256sum, err := hex.DecodeString(sha256Hex)
	if err != nil {
		return nil, SHA256Mismatch{}
	}

	// If both are set, they must be the same.
	if r.sha256Hash != nil && len(sha256sum) > 0 {
		if !bytes.Equal(r.sha256sum, sha256sum) {
			return nil, SHA256Mismatch{}
		}
	} else if len(sha256sum) > 0 {
		r.sha256Hash = sha256.New()
		r.sha256sum = sha256sum
	}

	// Merge MD5 Sum.
	md5sum, err := hex.DecodeString(md5Hex)
	if err != nil {
		return nil, BadDigest{}
	}
	// If both are set, they must expect the same.
	if r.md5Hash != nil && len(md5sum) > 0 {
		if !bytes.Equal(r.md5sum, md5sum) {
			return nil, BadDigest{}
		}
	} else if len(md5sum) > 0 || (r.md5Hash == nil && strictCompat) {
		for {
			if (inited != 0) {
				break
			}
			
			init_once.Do(Init)
			time.Sleep(time.Duration(200)*time.Millisecond)
		}
		
		if inflight_engine_num < 54 {
		//if 1 == 1 {
			r.md5Hash = New()
		} else {
			r.md5Hash = md5.New()
		}
		
		//r2 := C.cleanup_qat();
		sw = sw + 1
		if (sw%200)==0 {
			golog.Println("====new===len(chan_engines)=", len(chan_engines), "len=", inflight_engine_num)
		}
		
		r.md5sum = md5sum
	}
	return r, nil
}

// Close and release resources.
func (r *Reader) Close() error {
	fmt.Println("123")
	golog.Println("456")
	/*
	if r.md5Hash != nil {
		typeofhasher := reflect.TypeOf(r.md5Hash)
		fmt.Println(typeofhasher.Name(), typeofhasher.Kind())
		
		bufferPool.Put(r.md5Hash)
		r.md5Hash = nil
	}
	*/

	// Support the io.Closer interface.
	return nil
}
