/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *	  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var repeatingRemove = function(){
	$(this).parents('.repeating-item').remove();
	return false;
}
$('.repeating-remove').click(repeatingRemove);
$('.repeating-add').click(function(){
	var idx = $('.repeating-container').data('length');
	var div = $('.repeating-container').append('<tr class="repeating-item"><td>'+'<input type="text"  name="acl-path-'
			+ idx + '"  style="width:100%" /></td><td>'+
			'<input type="text" list="data-privileges" name="acl-privilege-' + idx + '" style="width:100%" />'+
			'</td><td><input type="button" value="-" class="repeating-remove" /></td></tr>');
	$('.repeating-container').data('length', idx + 1);
	$(div).find('.repeating-remove').click(repeatingRemove);
	return false;
});